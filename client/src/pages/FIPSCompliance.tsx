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

        {/* Audit Runner */}
        <AuditRunner />

        {/* History */}
        <ComplianceHistory />
      </div>
    </AppShell>
  );
}
