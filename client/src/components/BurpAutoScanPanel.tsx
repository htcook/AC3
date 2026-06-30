/**
 * BurpAutoScanPanel — Auto-launch and monitor Burp Suite scans from engagement ops.
 *
 * Shows connected Burp instances, allows launching scans against in-scope assets,
 * displays real-time progress, and shows persisted scan history from the database.
 */
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { toast } from "sonner";
import {
  Play, Square, Loader2, CheckCircle2, XCircle, AlertTriangle,
  ChevronDown, ChevronUp, Globe, Shield, Bug, RefreshCw, Scan,
  History, ArrowRight, Zap,
} from "lucide-react";

interface BurpAutoScanPanelProps {
  engagementId: number;
}

export default function BurpAutoScanPanel({ engagementId }: BurpAutoScanPanelProps) {
  const [showAuthConfig, setShowAuthConfig] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [appUsername, setAppUsername] = useState("");
  const [appPassword, setAppPassword] = useState("");
  const [appLoginUrl, setAppLoginUrl] = useState("");
  const [scanConfigName, setScanConfigName] = useState("");

  // Fetch Burp Suite credentials
  const credsQ = trpc.platformCredentials.list.useQuery();
  const burpCreds = (credsQ.data || []).filter(
    (c: any) => c.platform === "burpsuite_pro" || c.platform === "burpsuite_enterprise"
  );

  // Fetch active scan progress (in-memory, real-time)
  const progressQ = trpc.bugBounty.getBurpAutoScanProgress.useQuery(
    { engagementId },
    { refetchInterval: 5000 }
  );

  // Fetch persisted scan history from DB
  const historyQ = trpc.bugBounty.getBurpScanHistory.useQuery(
    { engagementId },
    { refetchInterval: 30000 }
  );

  const launchMutation = trpc.bugBounty.launchBurpAutoScan.useMutation({
    onSuccess: (data) => {
      toast.success(`Burp ${data.edition} scan launched against ${data.targetUrls.length} targets`);
      progressQ.refetch();
    },
    onError: (err) => {
      toast.error(`Failed to launch scan: ${err.message}`);
    },
  });

  const cancelMutation = trpc.bugBounty.cancelBurpAutoScan.useMutation({
    onSuccess: () => {
      toast.info("Burp scan cancelled");
      progressQ.refetch();
    },
    onError: (err) => {
      toast.error(`Failed to cancel: ${err.message}`);
    },
  });

  const scans = progressQ.data?.scans || [];
  const history = historyQ.data?.history || [];
  const hasActiveScans = scans.some(
    (s: any) => ["launching", "running", "polling", "importing"].includes(s.status)
  );

  function handleLaunch(credId: number) {
    const appLogin = appUsername && appPassword
      ? { username: appUsername, password: appPassword, loginUrl: appLoginUrl || undefined }
      : undefined;

    launchMutation.mutate({
      engagementId,
      credentialId: credId,
      scanConfigName: scanConfigName || undefined,
      appLogin,
    });
  }

  if (burpCreds.length === 0) {
    return (
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardContent className="py-8 text-center">
          <Scan className="h-10 w-10 text-zinc-600 mx-auto mb-3" />
          <p className="text-sm text-zinc-400 mb-1">No Burp Suite instances connected</p>
          <p className="text-xs text-zinc-500">
            Add Burp Suite credentials in the Bug Bounty Hub → Accounts tab to enable auto-scanning
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Connected Instances & Active Scans */}
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Scan className="h-4 w-4 text-orange-400" />
            Burp Suite Auto-Scan
            {hasActiveScans && (
              <Badge variant="outline" className="text-[10px] border-orange-500/30 text-orange-400 animate-pulse">
                SCANNING
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Credential selector */}
          {burpCreds.map((cred: any) => {
            const edition = cred.platform === "burpsuite_enterprise" ? "Enterprise" : "Professional";
            const activeScan = scans.find((s: any) => s.credentialId === cred.id);
            const isActive = activeScan && ["launching", "running", "polling", "importing"].includes(activeScan.status);

            return (
              <div key={cred.id} className="rounded-lg border border-zinc-700/50 bg-zinc-800/30 p-3 space-y-2">
                {/* Instance header */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="h-2 w-2 rounded-full bg-orange-400" />
                    <span className="text-xs font-medium text-zinc-200">
                      Burp {edition}
                    </span>
                    <span className="text-[10px] text-zinc-500">
                      {cred.baseUrl || "localhost:1337"}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    {isActive ? (
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs border-red-500/30 text-red-400 hover:bg-red-500/10"
                        onClick={() => cancelMutation.mutate({ engagementId, credentialId: cred.id })}
                        disabled={cancelMutation.isPending}
                      >
                        <Square className="h-3 w-3 mr-1" />
                        Cancel
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs border-orange-500/30 text-orange-400 hover:bg-orange-500/10"
                        onClick={() => handleLaunch(cred.id)}
                        disabled={launchMutation.isPending}
                      >
                        {launchMutation.isPending ? (
                          <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                        ) : (
                          <Play className="h-3 w-3 mr-1" />
                        )}
                        Launch Scan
                      </Button>
                    )}
                  </div>
                </div>

                {/* Active scan progress */}
                {activeScan && (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-zinc-400 flex items-center gap-1">
                        <StatusIcon status={activeScan.status} />
                        {statusLabel(activeScan.status)}
                      </span>
                      <span className="text-zinc-500">
                        {activeScan.issueCount} issues found
                        {activeScan.importedCount > 0 && ` · ${activeScan.importedCount} imported`}
                      </span>
                    </div>
                    <Progress
                      value={activeScan.progress}
                      className="h-1.5"
                    />
                    <div className="flex items-center justify-between text-[10px] text-zinc-500">
                      <span>{activeScan.targetUrls?.length || 0} targets</span>
                      <span>{activeScan.progress}%</span>
                    </div>
                    {activeScan.error && (
                      <div className="text-[10px] text-red-400 bg-red-500/10 rounded px-2 py-1 mt-1">
                        {activeScan.error}
                      </div>
                    )}
                  </div>
                )}

                {/* Completed scan summary with exploit chain indicator */}
                {activeScan && activeScan.status === "completed" && (
                  <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-md p-2 text-[10px]">
                    <div className="flex items-center gap-1 text-emerald-400 mb-1">
                      <CheckCircle2 className="h-3 w-3" />
                      Scan Complete
                    </div>
                    <div className="text-zinc-400">
                      {activeScan.issueCount} issues found · {activeScan.importedCount} imported as findings ·
                      Duration: {formatDuration(activeScan.startedAt, activeScan.completedAt)}
                    </div>
                    {activeScan.importedCount > 0 && (
                      <div className="flex items-center gap-1 text-amber-400 mt-1.5">
                        <Zap className="h-3 w-3" />
                        <span>Findings auto-matched against exploit database</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}

          {/* Scan configuration */}
          <Collapsible open={showAuthConfig} onOpenChange={setShowAuthConfig}>
            <CollapsibleTrigger asChild>
              <Button variant="ghost" size="sm" className="w-full text-xs text-zinc-500 hover:text-zinc-300 h-7">
                {showAuthConfig ? <ChevronUp className="h-3 w-3 mr-1" /> : <ChevronDown className="h-3 w-3 mr-1" />}
                Scan Configuration
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent className="space-y-3 pt-2">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label className="text-[10px] text-zinc-500">Scan Config Name</Label>
                  <Input
                    value={scanConfigName}
                    onChange={(e) => setScanConfigName(e.target.value)}
                    placeholder="e.g., Audit checks - all"
                    className="h-7 text-xs bg-zinc-800/50 border-zinc-700"
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-[10px] text-zinc-500">Login URL</Label>
                  <Input
                    value={appLoginUrl}
                    onChange={(e) => setAppLoginUrl(e.target.value)}
                    placeholder="https://app.example.com/login"
                    className="h-7 text-xs bg-zinc-800/50 border-zinc-700"
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-[10px] text-zinc-500">App Username</Label>
                  <Input
                    value={appUsername}
                    onChange={(e) => setAppUsername(e.target.value)}
                    placeholder="test@example.com"
                    className="h-7 text-xs bg-zinc-800/50 border-zinc-700"
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-[10px] text-zinc-500">App Password</Label>
                  <Input
                    type="password"
                    value={appPassword}
                    onChange={(e) => setAppPassword(e.target.value)}
                    placeholder="••••••••"
                    className="h-7 text-xs bg-zinc-800/50 border-zinc-700"
                  />
                </div>
              </div>
              <p className="text-[10px] text-zinc-600">
                Optional: provide app credentials for authenticated scanning. The scan config name maps to a named Burp Suite scan configuration.
              </p>
            </CollapsibleContent>
          </Collapsible>
        </CardContent>
      </Card>

      {/* Scan History (persisted in DB) */}
      {history.length > 0 && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader className="pb-2">
            <Collapsible open={showHistory} onOpenChange={setShowHistory}>
              <CollapsibleTrigger asChild>
                <CardTitle className="text-sm flex items-center gap-2 cursor-pointer hover:text-zinc-200 transition-colors">
                  <History className="h-4 w-4 text-zinc-400" />
                  Scan History
                  <Badge variant="outline" className="text-[10px] border-zinc-700 text-zinc-400">
                    {history.length}
                  </Badge>
                  {showHistory ? <ChevronUp className="h-3 w-3 ml-auto text-zinc-500" /> : <ChevronDown className="h-3 w-3 ml-auto text-zinc-500" />}
                </CardTitle>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <div className="space-y-2 pt-3">
                  {history.map((record: any) => (
                    <div
                      key={record.id}
                      className="rounded-md border border-zinc-700/30 bg-zinc-800/20 p-2.5 space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <StatusIcon status={record.status} />
                          <span className="text-xs text-zinc-300">
                            Burp {record.edition === "enterprise" ? "Enterprise" : "Pro"}
                          </span>
                          <span className="text-[10px] text-zinc-500">
                            {record.scanId ? `#${record.scanId.slice(0, 8)}` : "—"}
                          </span>
                        </div>
                        <Badge
                          variant="outline"
                          className={`text-[10px] ${
                            record.status === "completed"
                              ? "border-emerald-500/30 text-emerald-400"
                              : record.status === "failed"
                              ? "border-red-500/30 text-red-400"
                              : record.status === "cancelled"
                              ? "border-yellow-500/30 text-yellow-400"
                              : "border-zinc-600 text-zinc-400"
                          }`}
                        >
                          {statusLabel(record.status)}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between text-[10px] text-zinc-500">
                        <span>
                          {Array.isArray(record.targetUrls) ? record.targetUrls.length : 0} targets
                          {record.issueCount > 0 && ` · ${record.issueCount} issues`}
                          {record.importedCount > 0 && ` · ${record.importedCount} imported`}
                        </span>
                        <span>
                          {record.startedAt ? new Date(record.startedAt).toLocaleString() : "—"}
                        </span>
                      </div>
                      {record.progress > 0 && record.progress < 100 && (
                        <Progress value={record.progress} className="h-1" />
                      )}
                      {record.error && (
                        <div className="text-[10px] text-red-400 bg-red-500/10 rounded px-2 py-0.5">
                          {record.error}
                        </div>
                      )}
                      {record.status === "completed" && record.importedCount > 0 && (
                        <div className="flex items-center gap-1 text-[10px] text-amber-400">
                          <Zap className="h-2.5 w-2.5" />
                          Findings fed to exploit matching engine
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </CollapsibleContent>
            </Collapsible>
          </CardHeader>
        </Card>
      )}
    </div>
  );
}

// ─── Helpers ───

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "launching":
    case "running":
    case "polling":
      return <Loader2 className="h-3 w-3 animate-spin text-orange-400" />;
    case "importing":
      return <RefreshCw className="h-3 w-3 animate-spin text-blue-400" />;
    case "completed":
      return <CheckCircle2 className="h-3 w-3 text-emerald-400" />;
    case "failed":
      return <XCircle className="h-3 w-3 text-red-400" />;
    case "cancelled":
      return <AlertTriangle className="h-3 w-3 text-yellow-400" />;
    default:
      return <Globe className="h-3 w-3 text-zinc-400" />;
  }
}

function statusLabel(status: string): string {
  const labels: Record<string, string> = {
    pending: "Pending",
    launching: "Launching scan...",
    running: "Scanning in progress",
    polling: "Monitoring scan",
    importing: "Importing findings...",
    completed: "Scan complete",
    failed: "Scan failed",
    cancelled: "Cancelled",
  };
  return labels[status] || status;
}

function formatDuration(startMs: number, endMs: number | null): string {
  if (!endMs) return "—";
  const seconds = Math.floor((endMs - startMs) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}
