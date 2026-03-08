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
  Database,
  ArrowRightLeft,
  ShieldPlus,
  Award,
  Trash2,
  Download,
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
            {(data.complianceLevel || '').toUpperCase()}
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
                {(scheduledAuditMut.data.overallStatus || '').toUpperCase()}
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

// ─── Credential Migration Panel ──────────────────────────────────────────

function CredentialMigrationPanel() {
  const scanQuery = trpc.agentManager.scanCredentialMigration.useQuery(undefined, {
    refetchInterval: 30_000,
  });
  const migrateMutation = trpc.agentManager.runCredentialMigration.useMutation({
    onSuccess: (report) => {
      toast.success(
        `Migration complete: ${report.summary.totalMigrated} migrated, ${report.summary.totalFailed} failed (${report.durationMs}ms)`
      );
      scanQuery.refetch();
    },
    onError: (err) => toast.error(`Migration failed: ${err.message}`),
  });

  const scan = scanQuery.data;

  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardHeader>
        <CardTitle className="text-zinc-100 flex items-center gap-2">
          <Database className="h-5 w-5 text-blue-400" />
          Credential Migration to FIPS
        </CardTitle>
        <CardDescription>
          Detect and re-encrypt legacy credentials with FIPS 140-3 approved cryptography
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {scanQuery.isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-20 w-full" />
          </div>
        ) : scan ? (
          <>
            {/* Summary Bar */}
            <div className="flex items-center gap-4 p-4 rounded-lg bg-zinc-800/50 border border-zinc-700/50">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  {scan.summary.migrationNeeded ? (
                    <AlertTriangle className="h-5 w-5 text-amber-400" />
                  ) : (
                    <CheckCircle className="h-5 w-5 text-emerald-400" />
                  )}
                  <span className="text-sm font-medium text-zinc-200">
                    {scan.summary.migrationNeeded
                      ? `${scan.summary.totalLegacy} credentials need FIPS migration`
                      : "All credentials are FIPS-encrypted"}
                  </span>
                </div>
                {/* Progress bar */}
                <div className="w-full bg-zinc-700 rounded-full h-2">
                  <div
                    className="bg-emerald-500 h-2 rounded-full transition-all"
                    style={{ width: `${scan.summary.fipsPercentage}%` }}
                  />
                </div>
                <div className="text-xs text-zinc-500 mt-1">
                  {scan.summary.totalFips} / {scan.summary.totalCredentials} FIPS-encrypted ({scan.summary.fipsPercentage}%)
                </div>
              </div>
              <Button
                size="sm"
                onClick={() => migrateMutation.mutate()}
                disabled={!scan.summary.migrationNeeded || migrateMutation.isPending}
                className="bg-blue-600 hover:bg-blue-500"
              >
                {migrateMutation.isPending ? (
                  <RefreshCw className="h-4 w-4 animate-spin mr-1" />
                ) : (
                  <ArrowRightLeft className="h-4 w-4 mr-1" />
                )}
                {migrateMutation.isPending ? "Migrating..." : "Run Migration"}
              </Button>
            </div>

            {/* Breakdown Table */}
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 rounded-lg bg-zinc-800/30 border border-zinc-700/30">
                <div className="text-xs text-zinc-500 mb-1">Server Credentials</div>
                <div className="text-lg font-mono text-zinc-200">{scan.serverCredentials.total}</div>
                <div className="text-xs text-zinc-500">
                  <span className="text-emerald-400">{scan.serverCredentials.fips} FIPS</span>
                  {scan.serverCredentials.legacy > 0 && (
                    <span className="text-amber-400 ml-2">{scan.serverCredentials.legacy} legacy</span>
                  )}
                  {scan.serverCredentials.plaintext > 0 && (
                    <span className="text-red-400 ml-2">{scan.serverCredentials.plaintext} plaintext</span>
                  )}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-zinc-800/30 border border-zinc-700/30">
                <div className="text-xs text-zinc-500 mb-1">SSH Keys</div>
                <div className="text-lg font-mono text-zinc-200">{scan.sshKeys.total}</div>
                <div className="text-xs text-zinc-500">
                  <span className="text-emerald-400">{scan.sshKeys.fips} FIPS</span>
                  {scan.sshKeys.legacy > 0 && (
                    <span className="text-amber-400 ml-2">{scan.sshKeys.legacy} legacy</span>
                  )}
                  {scan.sshKeys.plaintext > 0 && (
                    <span className="text-red-400 ml-2">{scan.sshKeys.plaintext} plaintext</span>
                  )}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-zinc-800/30 border border-zinc-700/30">
                <div className="text-xs text-zinc-500 mb-1">Cloud Credentials</div>
                <div className="text-lg font-mono text-zinc-200">{scan.cloudCredentials.total}</div>
                <div className="text-xs text-zinc-500">
                  <span className="text-emerald-400">{scan.cloudCredentials.fips} FIPS</span>
                  {scan.cloudCredentials.legacy > 0 && (
                    <span className="text-amber-400 ml-2">{scan.cloudCredentials.legacy} legacy</span>
                  )}
                </div>
              </div>
            </div>
          </>
        ) : (
          <p className="text-sm text-zinc-500">Unable to scan credentials</p>
        )}
      </CardContent>
    </Card>
  );
}

// ─── mTLS Certificate Panel ─────────────────────────────────────────────

function MTLSCertificatePanel() {
  const certsQuery = trpc.agentManager.listMTLSCerts.useQuery(undefined, {
    refetchInterval: 30_000,
  });
  const ensureCAMutation = trpc.agentManager.ensureMTLSCA.useMutation({
    onSuccess: () => {
      toast.success("Internal CA initialized");
      certsQuery.refetch();
    },
    onError: (err) => toast.error(`CA initialization failed: ${err.message}`),
  });
  const revokeMutation = trpc.agentManager.revokeMTLSCert.useMutation({
    onSuccess: () => {
      toast.success("Certificate revoked");
      certsQuery.refetch();
    },
    onError: (err) => toast.error(`Revocation failed: ${err.message}`),
  });

  const certs = certsQuery.data ?? [];
  const caCerts = certs.filter((c) => c.type === "ca");
  const clientCerts = certs.filter((c) => c.type === "client");
  const hasCA = caCerts.some((c) => c.status === "active");

  function handleDownload(cert: { certificate: string; commonName: string }) {
    const blob = new Blob([cert.certificate], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${cert.commonName.replace(/[^a-zA-Z0-9.-]/g, "_")}.pem`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-zinc-100 flex items-center gap-2">
              <Award className="h-5 w-5 text-purple-400" />
              mTLS Client Certificates
            </CardTitle>
            <CardDescription>
              ECDSA P-256 client certificates for mutual TLS authentication with C2 servers
            </CardDescription>
          </div>
          {!hasCA && (
            <Button
              size="sm"
              onClick={() => ensureCAMutation.mutate()}
              disabled={ensureCAMutation.isPending}
              className="bg-purple-600 hover:bg-purple-500"
            >
              {ensureCAMutation.isPending ? (
                <RefreshCw className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <ShieldPlus className="h-4 w-4 mr-1" />
              )}
              Initialize CA
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {certsQuery.isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-16 w-full" />
          </div>
        ) : (
          <>
            {/* CA Status */}
            <div className="p-4 rounded-lg bg-zinc-800/50 border border-zinc-700/50">
              <div className="flex items-center gap-2 mb-2">
                {hasCA ? (
                  <CheckCircle className="h-5 w-5 text-emerald-400" />
                ) : (
                  <AlertTriangle className="h-5 w-5 text-amber-400" />
                )}
                <span className="text-sm font-medium text-zinc-200">
                  {hasCA ? "Internal CA Active" : "No Internal CA — initialize to enable mTLS"}
                </span>
              </div>
              {caCerts.filter((c) => c.status === "active").map((ca) => (
                <div key={ca.id} className="text-xs text-zinc-500 space-y-1 mt-2">
                  <div>CN: <span className="text-zinc-400 font-mono">{ca.commonName}</span></div>
                  <div>Fingerprint: <span className="text-zinc-400 font-mono">{ca.fingerprint.slice(0, 32)}...</span></div>
                  <div>Valid: {formatTimestamp(ca.validFrom)} → {formatTimestamp(ca.validTo)}</div>
                  <div>Algorithm: <Badge variant="outline" className="text-xs">ECDSA P-256 + SHA-256</Badge></div>
                </div>
              ))}
            </div>

            {/* Client Certificates */}
            {clientCerts.length > 0 ? (
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-zinc-300">Client Certificates ({clientCerts.length})</h4>
                {clientCerts.map((cert) => (
                  <div
                    key={cert.id}
                    className="flex items-center justify-between p-3 rounded-lg bg-zinc-800/30 border border-zinc-700/30"
                  >
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <Key className="h-4 w-4 text-zinc-500" />
                        <span className="text-sm font-mono text-zinc-300">{cert.commonName}</span>
                        <Badge
                          variant="outline"
                          className={cert.status === "active"
                            ? "text-emerald-400 border-emerald-500/30"
                            : cert.status === "revoked"
                            ? "text-red-400 border-red-500/30"
                            : "text-amber-400 border-amber-500/30"}
                        >
                          {cert.status}
                        </Badge>
                      </div>
                      <div className="text-xs text-zinc-500 mt-1">
                        Serial: {cert.serialNumber.slice(0, 16)}... | Expires: {formatTimestamp(cert.validTo)}
                        {cert.c2ServerId && <span> | Server: {cert.c2ServerId.slice(0, 8)}...</span>}
                      </div>
                    </div>
                    <div className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleDownload(cert)}
                        title="Download PEM"
                      >
                        <Download className="h-4 w-4" />
                      </Button>
                      {cert.status === "active" && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => revokeMutation.mutate({ id: cert.id })}
                          disabled={revokeMutation.isPending}
                          title="Revoke"
                          className="text-red-400 hover:text-red-300"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : hasCA ? (
              <p className="text-sm text-zinc-500">
                No client certificates issued yet. Issue certificates from the Agent Manager when adding C2 servers.
              </p>
            ) : null}
          </>
        )}
      </CardContent>
    </Card>
  );
}

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
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Audit and track FIPS 140-2/140-3 cryptographic compliance across your infrastructure. This page scans for non-compliant cryptographic implementations — weak ciphers, unapproved algorithms, and misconfigured TLS settings. View compliance status by asset, drill into specific violations, and generate compliance reports for federal and regulated environments.</p>
          <p className="text-sm text-zinc-500 mt-1">
            Platform-wide cryptographic compliance monitoring, algorithm validation, and audit trail
          </p>
        </div>

        {/* Status */}
        <FIPSStatusCard />

        {/* Credential Migration */}
        <CredentialMigrationPanel />

        {/* mTLS Certificates */}
        <MTLSCertificatePanel />

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
