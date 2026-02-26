import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import {
  Lock,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Key,
  Fingerprint,
  Activity,
  Clock,
  Server,
  FileText,
  Copy,
} from "lucide-react";

function formatTimestamp(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleString();
}

function complianceStatusBadge(status: string) {
  if (status === "compliant") {
    return <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20">Compliant</Badge>;
  }
  if (status === "warning") {
    return <Badge className="bg-amber-500/10 text-amber-400 border-amber-500/20">Warning</Badge>;
  }
  return <Badge className="bg-red-500/10 text-red-400 border-red-500/20">Non-Compliant</Badge>;
}

function complianceIcon(status: string) {
  if (status === "compliant") return <CheckCircle className="h-5 w-5 text-emerald-400" />;
  if (status === "warning") return <AlertTriangle className="h-5 w-5 text-amber-400" />;
  return <XCircle className="h-5 w-5 text-red-400" />;
}

// ─── FIPS Status Card ─────────────────────────────────────────────────────

function FIPSStatusCard() {
  const { data, isLoading } = trpc.agentManager.fipsStatus.useQuery();

  if (isLoading) {
    return (
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardContent className="p-6">
          <Skeleton className="h-8 w-48 mb-4" />
          <Skeleton className="h-4 w-full mb-2" />
          <Skeleton className="h-4 w-3/4" />
        </CardContent>
      </Card>
    );
  }

  if (!data) return null;

  const isFullFips = data.fipsProviderActive;

  return (
    <Card className={`border ${isFullFips ? "border-emerald-500/30 bg-emerald-500/5" : "border-amber-500/30 bg-amber-500/5"}`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-lg">
            {isFullFips ? (
              <ShieldCheck className="h-6 w-6 text-emerald-400" />
            ) : (
              <Shield className="h-6 w-6 text-amber-400" />
            )}
            FIPS 140-3 Compliance Status
          </CardTitle>
          <Badge className={isFullFips ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-amber-500/10 text-amber-400 border-amber-500/20"}>
            {data.complianceLevel.toUpperCase()}
          </Badge>
        </div>
        <CardDescription>
          {isFullFips
            ? "OpenSSL FIPS provider is active. All cryptographic operations route through a validated module."
            : "Running in software-only mode. All algorithms are FIPS-approved, but not executing through a FIPS-validated module."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          <div className="p-3 rounded-lg bg-zinc-900/50 border border-zinc-800">
            <p className="text-xs text-zinc-500 mb-1">OpenSSL Version</p>
            <p className="text-sm font-mono text-zinc-300">{data.opensslVersion || "Unknown"}</p>
          </div>
          <div className="p-3 rounded-lg bg-zinc-900/50 border border-zinc-800">
            <p className="text-xs text-zinc-500 mb-1">Node.js Version</p>
            <p className="text-sm font-mono text-zinc-300">{data.nodeVersion}</p>
          </div>
          <div className="p-3 rounded-lg bg-zinc-900/50 border border-zinc-800">
            <p className="text-xs text-zinc-500 mb-1">FIPS Provider</p>
            <p className={`text-sm font-medium ${isFullFips ? "text-emerald-400" : "text-amber-400"}`}>
              {isFullFips ? "Active" : "Inactive"}
            </p>
          </div>
        </div>

        {/* Approved Algorithms */}
        <div className="mt-4 space-y-3">
          <h4 className="text-sm font-medium text-zinc-300">Approved Algorithms</h4>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {Object.entries(data.approvedAlgorithms).map(([category, algorithms]) => (
              <div key={category} className="p-3 rounded-lg bg-zinc-900/50 border border-zinc-800">
                <p className="text-xs text-zinc-500 mb-1.5 uppercase">{category}</p>
                <div className="flex flex-wrap gap-1">
                  {(algorithms as string[]).map((alg) => (
                    <span key={alg} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono bg-zinc-800 text-zinc-400 border border-zinc-700">
                      {alg}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Prohibited Algorithms */}
        <div className="mt-4">
          <h4 className="text-sm font-medium text-zinc-300 mb-2">Prohibited Algorithms</h4>
          <div className="flex flex-wrap gap-1">
            {data.prohibitedAlgorithms.map((alg) => (
              <span key={alg} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono bg-red-500/10 text-red-400 border border-red-500/20 line-through">
                {alg}
              </span>
            ))}
          </div>
        </div>

        {/* TLS Ciphers */}
        <div className="mt-4 space-y-2">
          <h4 className="text-sm font-medium text-zinc-300">TLS Cipher Suites</h4>
          <div className="p-3 rounded-lg bg-zinc-900/50 border border-zinc-800">
            <p className="text-xs text-zinc-500 mb-1">TLS 1.2</p>
            <p className="text-xs font-mono text-zinc-400 break-all">{data.tlsCiphers.tls12}</p>
          </div>
          <div className="p-3 rounded-lg bg-zinc-900/50 border border-zinc-800">
            <p className="text-xs text-zinc-500 mb-1">TLS 1.3</p>
            <p className="text-xs font-mono text-zinc-400 break-all">{data.tlsCiphers.tls13}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Audit Runner ─────────────────────────────────────────────────────────

function AuditRunner() {
  const utils = trpc.useUtils();
  const auditMut = trpc.agentManager.fipsAudit.useMutation({
    onSuccess: (data) => {
      if (data.overallStatus === "compliant") {
        toast.success("All FIPS compliance checks passed");
      } else if (data.overallStatus === "warning") {
        toast.warning("FIPS audit completed with warnings");
      } else {
        toast.error("FIPS audit found non-compliant items");
      }
      utils.agentManager.fipsHistory.invalidate();
    },
    onError: (e) => toast.error(e.message),
  });

  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Activity className="h-5 w-5 text-blue-400" />
            Run Compliance Audit
          </CardTitle>
          <Button
            onClick={() => auditMut.mutate()}
            disabled={auditMut.isPending}
            className="bg-blue-600 hover:bg-blue-700"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${auditMut.isPending ? "animate-spin" : ""}`} />
            {auditMut.isPending ? "Running..." : "Run Audit"}
          </Button>
        </div>
        <CardDescription>
          Tests AES-256-GCM, ECDSA P-256, HMAC-SHA256, PBKDF2, and FIPS provider status.
        </CardDescription>
      </CardHeader>

      {auditMut.data && (
        <CardContent>
          <div className="space-y-2">
            {auditMut.data.checks.map((check, i) => (
              <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50">
                <div className="flex items-center gap-3">
                  {complianceIcon(check.status)}
                  <div>
                    <p className="text-sm font-medium text-zinc-300">{check.component}</p>
                    <p className="text-xs text-zinc-500">{check.checkType.replace(/_/g, " ")}</p>
                  </div>
                </div>
                {complianceStatusBadge(check.status)}
              </div>
            ))}
          </div>
        </CardContent>
      )}
    </Card>
  );
}

// ─── Scheduled Audit Panel ───────────────────────────────────────────────

function ScheduledAuditPanel() {
  const utils = trpc.useUtils();
  const scheduledAuditMut = trpc.agentManager.runScheduledFipsAudit.useMutation({
    onSuccess: (data) => {
      utils.agentManager.fipsHistory.invalidate();
      if (data.overallStatus === "compliant") {
        toast.success("Scheduled audit passed — all checks compliant");
      } else if (data.degraded) {
        toast.error(`Compliance DEGRADED — owner ${data.notificationSent ? "notified" : "notification failed"}`);
      } else {
        toast.warning(`Audit completed: ${data.overallStatus}`);
      }
    },
    onError: (e) => toast.error(e.message),
  });

  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Clock className="h-5 w-5 text-purple-400" />
            Scheduled Compliance Audit
          </CardTitle>
          <Button
            onClick={() => scheduledAuditMut.mutate()}
            disabled={scheduledAuditMut.isPending}
            variant="outline"
            className="text-purple-400 border-purple-500/30 hover:bg-purple-500/10"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${scheduledAuditMut.isPending ? "animate-spin" : ""}`} />
            {scheduledAuditMut.isPending ? "Running..." : "Run Now"}
          </Button>
        </div>
        <CardDescription>
          Runs automatically daily at 02:00 UTC. Compares results against previous audit and sends
          owner notifications on compliance degradation.
        </CardDescription>
      </CardHeader>

      {scheduledAuditMut.data && (
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            <div className="p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50 text-center">
              <p className={`text-lg font-bold ${
                scheduledAuditMut.data.overallStatus === "compliant" ? "text-emerald-400" :
                scheduledAuditMut.data.overallStatus === "warning" ? "text-amber-400" : "text-red-400"
              }`}>
                {scheduledAuditMut.data.overallStatus.toUpperCase()}
              </p>
              <p className="text-xs text-zinc-500">Overall Status</p>
            </div>
            <div className="p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50 text-center">
              <p className="text-lg font-bold text-zinc-300">{scheduledAuditMut.data.checks.length}</p>
              <p className="text-xs text-zinc-500">Checks Run</p>
            </div>
            <div className="p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50 text-center">
              <p className={`text-lg font-bold ${scheduledAuditMut.data.degraded ? "text-red-400" : "text-emerald-400"}`}>
                {scheduledAuditMut.data.degraded ? "YES" : "NO"}
              </p>
              <p className="text-xs text-zinc-500">Degraded</p>
            </div>
            <div className="p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50 text-center">
              <p className={`text-lg font-bold ${scheduledAuditMut.data.notificationSent ? "text-blue-400" : "text-zinc-500"}`}>
                {scheduledAuditMut.data.notificationSent ? "SENT" : "—"}
              </p>
              <p className="text-xs text-zinc-500">Notification</p>
            </div>
          </div>

          <div className="space-y-2">
            {scheduledAuditMut.data.checks.map((check, i) => (
              <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50">
                <div className="flex items-center gap-3">
                  {complianceIcon(check.status)}
                  <div>
                    <p className="text-sm font-medium text-zinc-300">{check.component}</p>
                    <p className="text-xs text-zinc-500">{check.checkType.replace(/_/g, " ")}</p>
                  </div>
                </div>
                {complianceStatusBadge(check.status)}
              </div>
            ))}
          </div>
        </CardContent>
      )}
    </Card>
  );
}

// ─── Compliance History ───────────────────────────────────────────────────

function ComplianceHistory() {
  const { data, isLoading } = trpc.agentManager.fipsHistory.useQuery({ limit: 50 });

  if (isLoading) {
    return <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>;
  }

  const records = data ?? [];

  // Group by createdAt (same audit run)
  const grouped = new Map<number, typeof records>();
  for (const r of records) {
    const key = r.createdAt;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)!.push(r);
  }

  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Clock className="h-5 w-5 text-zinc-400" />
          Audit History
        </CardTitle>
      </CardHeader>
      <CardContent>
        {records.length === 0 ? (
          <p className="text-sm text-zinc-500 text-center py-4">No audit records yet. Run an audit to generate compliance data.</p>
        ) : (
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {Array.from(grouped.entries()).map(([ts, checks]) => {
              const fullAudit = checks.find((c) => c.checkType === "full_audit");
              const overallStatus = fullAudit?.status ?? "warning";
              return (
                <div key={ts} className="p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {complianceIcon(overallStatus)}
                      <span className="text-sm font-medium text-zinc-300">{formatTimestamp(ts)}</span>
                    </div>
                    {complianceStatusBadge(overallStatus)}
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {checks
                      .filter((c) => c.checkType !== "full_audit")
                      .map((c, i) => (
                        <span
                          key={i}
                          className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs ${
                            c.status === "compliant"
                              ? "bg-emerald-500/10 text-emerald-400"
                              : c.status === "warning"
                              ? "bg-amber-500/10 text-amber-400"
                              : "bg-red-500/10 text-red-400"
                          }`}
                        >
                          {c.component}
                        </span>
                      ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── TLS Audit Panel ──────────────────────────────────────────────────────

function TLSAuditPanel() {
  const tlsAudit = trpc.agentManager.auditTLS.useQuery();
  const testConnection = trpc.agentManager.testTLSConnection.useMutation({
    onSuccess: (data) => {
      if (data.connected && data.fipsApproved) {
        toast.success(`TLS connection FIPS-compliant: ${data.protocol} / ${data.cipher}`);
      } else if (data.connected) {
        toast.warning(`Connected but cipher ${data.cipher} may not be FIPS-approved`);
      } else {
        toast.error(`Connection failed: ${data.error || "Unknown error"}`);
      }
    },
    onError: (e) => toast.error(e.message),
  });
  const [testHost, setTestHost] = useState("");

  if (tlsAudit.isLoading) return <Skeleton className="h-48 bg-zinc-800/50" />;

  const data = tlsAudit.data;

  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Server className="h-5 w-5 text-blue-400" />
          TLS Configuration Audit
        </CardTitle>
        <CardDescription>Data-in-transit FIPS compliance — cipher suites, protocol versions, and global enforcement</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Global Enforcement Status */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50">
            <div className="text-xs text-zinc-500 mb-1">Global TLS Enforcement</div>
            <div className="flex items-center gap-2">
              {data?.globalEnforcement ? (
                <><CheckCircle className="h-4 w-4 text-emerald-400" /><span className="text-sm text-emerald-400">Active</span></>
              ) : (
                <><XCircle className="h-4 w-4 text-red-400" /><span className="text-sm text-red-400">Inactive</span></>
              )}
            </div>
          </div>
          <div className="p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50">
            <div className="text-xs text-zinc-500 mb-1">Minimum TLS Version</div>
            <span className="text-sm font-mono text-zinc-200">{data?.minVersion || "—"}</span>
          </div>
          <div className="p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50">
            <div className="text-xs text-zinc-500 mb-1">FIPS Cipher Suites</div>
            <span className="text-sm font-mono text-zinc-200">{data?.cipherSuites?.length || 0} approved</span>
          </div>
        </div>

        {/* Cipher Suite List */}
        <div className="p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50">
          <div className="text-xs text-zinc-500 mb-2">Approved Cipher Suites (NIST SP 800-52 Rev. 2)</div>
          <div className="flex flex-wrap gap-1">
            {data?.cipherSuites?.map((cipher, i) => (
              <span key={i} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-emerald-500/10 text-emerald-400 font-mono">
                {cipher}
              </span>
            ))}
          </div>
        </div>

        {/* Non-Compliant Ciphers */}
        {data?.nonCompliantCiphers && data.nonCompliantCiphers.length > 0 && (
          <div className="p-3 rounded-lg bg-red-900/10 border border-red-800/30">
            <div className="text-xs text-red-400 mb-2 flex items-center gap-1">
              <AlertTriangle className="h-3 w-3" />
              Non-FIPS Ciphers in Node.js Defaults (blocked by global enforcement)
            </div>
            <div className="flex flex-wrap gap-1">
              {data.nonCompliantCiphers.slice(0, 10).map((cipher, i) => (
                <span key={i} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-red-500/10 text-red-400 font-mono line-through">
                  {cipher}
                </span>
              ))}
              {data.nonCompliantCiphers.length > 10 && (
                <span className="text-xs text-red-400">+{data.nonCompliantCiphers.length - 10} more</span>
              )}
            </div>
          </div>
        )}

        {/* Connection Tester */}
        <div className="p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50">
          <div className="text-xs text-zinc-500 mb-2">Test TLS Connection</div>
          <div className="flex gap-2">
            <input
              type="text"
              placeholder="hostname (e.g. api.example.com)"
              value={testHost}
              onChange={(e) => setTestHost(e.target.value)}
              className="flex-1 px-3 py-1.5 rounded bg-zinc-800 border border-zinc-700 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-amber-500/50"
            />
            <Button
              size="sm"
              variant="outline"
              disabled={!testHost || testConnection.isPending}
              onClick={() => testConnection.mutate({ hostname: testHost, port: 443 })}
            >
              {testConnection.isPending ? "Testing..." : "Test"}
            </Button>
          </div>
          {testConnection.data && (
            <div className="mt-2 text-xs space-y-1">
              <div className="flex items-center gap-2">
                {testConnection.data.fipsApproved ? (
                  <CheckCircle className="h-3 w-3 text-emerald-400" />
                ) : (
                  <AlertTriangle className="h-3 w-3 text-amber-400" />
                )}
                <span className="text-zinc-300">
                  {testConnection.data.connected ? "Connected" : "Failed"} — {testConnection.data.protocol} / {testConnection.data.cipher}
                </span>
              </div>
              {testConnection.data.error && (
                <div className="text-red-400">{testConnection.data.error}</div>
              )}
            </div>
          )}
        </div>

        <p className="text-xs text-zinc-600">{data?.details}</p>
      </CardContent>
    </Card>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────

export default function FIPSCompliance() {
  return (
    <AppShell>
      <div className="p-6 max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-3">
            <Lock className="h-7 w-7 text-amber-400" />
            FIPS 140-3 Compliance
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Platform-wide cryptographic compliance monitoring, algorithm validation, and audit trail
          </p>
        </div>

        {/* Status */}
        <FIPSStatusCard />

        {/* TLS Audit */}
        <TLSAuditPanel />

        {/* Audit Runner */}
        <AuditRunner />

        {/* Scheduled Audit */}
        <ScheduledAuditPanel />

        {/* History */}
        <ComplianceHistory />
      </div>
    </AppShell>
  );
}
