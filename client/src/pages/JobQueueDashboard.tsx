/**
 * Job Queue Dashboard — Redis-backed DO Worker Dispatch Management
 *
 * Monitor job queue health, worker status, FIPS compliance,
 * and infrastructure security posture.
 */
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Layers,
  Server,
  Activity,
  Shield,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  RefreshCw,
  Cpu,
  Lock,
  Key,
  Network,
  Eye,
} from "lucide-react";
import AppShell from "@/components/AppShell";
import { toast } from "sonner";

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatDuration(ms: number | null | undefined): string {
  if (!ms) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

function timeAgo(dateStr: string | null | undefined): string {
  if (!dateStr) return "—";
  const ms = Date.now() - new Date(dateStr).getTime();
  if (ms < 60_000) return "just now";
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return `${Math.floor(ms / 86_400_000)}d ago`;
}

const JOB_STATUS_COLORS: Record<string, string> = {
  queued: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  dispatched: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  running: "bg-cyan-500/20 text-cyan-300 border-cyan-500/40",
  completed: "bg-green-500/20 text-green-300 border-green-500/40",
  failed: "bg-red-500/20 text-red-300 border-red-500/40",
  timeout: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  cancelled: "bg-zinc-500/20 text-zinc-400 border-zinc-500/40",
};

// ─── Main Component ─────────────────────────────────────────────────────────

export default function JobQueueDashboard() {

  const [activeTab, setActiveTab] = useState("overview");
  const [jobTypeFilter, setJobTypeFilter] = useState<string>("all");

  const utils = trpc.useUtils();

  const { data: queueStats, isLoading: statsLoading } = trpc.jobQueue.stats.useQuery();
  const { data: history, isLoading: historyLoading } = trpc.jobQueue.history.useQuery({
    limit: 50,
    jobType: jobTypeFilter as any,
  });
  const { data: infraStatus } = trpc.jobQueue.infraStatus.useQuery();
  const { data: keyRotation } = trpc.jobQueue.keyRotation.useQuery();

  const complianceCheckMut = trpc.jobQueue.complianceCheck.useMutation({
    onSuccess: (data) => {
      if (data.overallCompliant) {
        toast.success(`FIPS Compliant — ${data.checks.filter((c: any) => c.status === "pass").length}/${data.checks.length} checks passed.`);
      } else {
        toast.error(`Compliance Issues Found — ${data.checks.filter((c: any) => c.status === "pass").length}/${data.checks.length} checks passed.`);
      }
    },
  });

  return (
    <AppShell activePath="/job-queue">
      <div className="space-y-6 p-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <Layers className="w-6 h-6 text-cyan-400" />
              Job Queue & Infrastructure
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Redis-backed worker dispatch, FIPS 140-3 compliance, and DO infrastructure management
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              utils.jobQueue.stats.invalidate();
              utils.jobQueue.history.invalidate();
              utils.jobQueue.infraStatus.invalidate();
            }}
          >
            <RefreshCw className="w-4 h-4 mr-1" /> Refresh
          </Button>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-muted/30">
            <TabsTrigger value="overview">Queue Overview</TabsTrigger>
            <TabsTrigger value="workers">Workers</TabsTrigger>
            <TabsTrigger value="history">Job History</TabsTrigger>
            <TabsTrigger value="fips">FIPS Compliance</TabsTrigger>
            <TabsTrigger value="infra">Infrastructure</TabsTrigger>
          </TabsList>

          {/* ─── Queue Overview Tab ──────────────────────────────────── */}
          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { label: "Queued", value: queueStats?.queued ?? 0, color: "text-amber-400", icon: Clock },
                { label: "Running", value: queueStats?.running ?? 0, color: "text-cyan-400", icon: Activity },
                { label: "Completed", value: queueStats?.completed ?? 0, color: "text-green-400", icon: CheckCircle2 },
                { label: "Failed", value: queueStats?.failed ?? 0, color: "text-red-400", icon: XCircle },
              ].map((s) => (
                <Card key={s.label} className="bg-card/50 border-border/50">
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2">
                      <s.icon className={`w-4 h-4 ${s.color}`} />
                      <span className="text-xs text-muted-foreground uppercase tracking-wider">{s.label}</span>
                    </div>
                    <p className={`text-2xl font-bold mt-1 ${s.color}`}>{s.value}</p>
                  </CardContent>
                </Card>
              ))}
            </div>

            {/* Queue Health */}
            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Network className="w-4 h-4 text-cyan-400" />
                  Queue Health
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Total Workers</p>
                    <p className="text-lg font-bold">{queueStats?.workerDetails?.length ?? 0}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Healthy Workers</p>
                    <p className="text-lg font-bold text-green-400">
                      {queueStats?.workerDetails?.filter((w: any) => w.healthy).length ?? 0}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">FIPS Compliant</p>
                    <p className="text-lg font-bold text-emerald-400">
                      {queueStats?.workerDetails?.filter((w: any) => w.fipsCompliant).length ?? 0}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">VPC-Only</p>
                    <p className="text-lg font-bold text-blue-400">
                      {queueStats?.workerDetails?.filter((w: any) => w.vpcOnly).length ?? 0}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* ─── Workers Tab ─────────────────────────────────────────── */}
          <TabsContent value="workers" className="space-y-4">
            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" />
                  Registered Workers
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border/50">
                      <TableHead>Worker ID</TableHead>
                      <TableHead>Host</TableHead>
                      <TableHead>Region</TableHead>
                      <TableHead>Types</TableHead>
                      <TableHead>Active Jobs</TableHead>
                      <TableHead>Health</TableHead>
                      <TableHead>FIPS</TableHead>
                      <TableHead>VPC</TableHead>
                      <TableHead>Last Heartbeat</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {!queueStats?.workerDetails?.length ? (
                      <TableRow>
                        <TableCell colSpan={9} className="text-center py-12">
                          <div className="space-y-2">
                            <Server className="w-10 h-10 text-muted-foreground/40 mx-auto" />
                            <p className="text-muted-foreground">No workers registered</p>
                            <p className="text-xs text-muted-foreground/60">
                              Workers will appear when DO scan infrastructure is provisioned
                            </p>
                          </div>
                        </TableCell>
                      </TableRow>
                    ) : (
                      queueStats.workerDetails.map((w: any) => (
                        <TableRow key={w.id} className="border-border/30">
                          <TableCell className="font-mono text-xs">{w.id}</TableCell>
                          <TableCell className="font-mono text-xs">{w.host}</TableCell>
                          <TableCell>{w.region}</TableCell>
                          <TableCell>
                            <div className="flex gap-1 flex-wrap">
                              {w.types?.map((t: string) => (
                                <Badge key={t} variant="outline" className="text-xs">{t}</Badge>
                              ))}
                            </div>
                          </TableCell>
                          <TableCell>{w.activeJobs}/{w.maxJobs}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className={w.healthy ? "bg-green-500/20 text-green-300" : "bg-red-500/20 text-red-300"}>
                              {w.healthy ? "Healthy" : "Unhealthy"}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            {w.fipsCompliant ? (
                              <ShieldCheck className="w-4 h-4 text-green-400" />
                            ) : (
                              <AlertTriangle className="w-4 h-4 text-red-400" />
                            )}
                          </TableCell>
                          <TableCell>
                            {w.vpcOnly ? (
                              <Lock className="w-4 h-4 text-blue-400" />
                            ) : (
                              <AlertTriangle className="w-4 h-4 text-orange-400" />
                            )}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {w.lastHeartbeat ? new Date(w.lastHeartbeat).toLocaleTimeString() : "—"}
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* ─── Job History Tab ──────────────────────────────────────── */}
          <TabsContent value="history" className="space-y-4">
            <div className="flex items-center gap-3">
              <Select value={jobTypeFilter} onValueChange={setJobTypeFilter}>
                <SelectTrigger className="w-[160px]">
                  <SelectValue placeholder="Job Type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Types</SelectItem>
                  <SelectItem value="scan">Scan</SelectItem>
                  <SelectItem value="recon">Recon</SelectItem>
                  <SelectItem value="feed">Feed</SelectItem>
                  <SelectItem value="c2">C2</SelectItem>
                </SelectContent>
              </Select>
              <span className="text-sm text-muted-foreground ml-auto">
                {history?.total ?? 0} jobs total
              </span>
            </div>

            <Card className="bg-card/50 border-border/50">
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border/50">
                      <TableHead>Job ID</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Worker</TableHead>
                      <TableHead>Duration</TableHead>
                      <TableHead>FIPS</TableHead>
                      <TableHead>Created</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {historyLoading ? (
                      <TableRow>
                        <TableCell colSpan={8} className="text-center py-12 text-muted-foreground">
                          Loading job history...
                        </TableCell>
                      </TableRow>
                    ) : !history?.items?.length ? (
                      <TableRow>
                        <TableCell colSpan={8} className="text-center py-12">
                          <div className="space-y-2">
                            <Layers className="w-10 h-10 text-muted-foreground/40 mx-auto" />
                            <p className="text-muted-foreground">No jobs in history</p>
                            <p className="text-xs text-muted-foreground/60">
                              Jobs will appear here when dispatched to DO workers
                            </p>
                          </div>
                        </TableCell>
                      </TableRow>
                    ) : (
                      history.items.map((job: any) => (
                        <TableRow key={job.id} className="border-border/30">
                          <TableCell className="font-mono text-xs">{job.jobId?.slice(0, 12)}...</TableCell>
                          <TableCell>
                            <Badge variant="outline">{job.jobType}</Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={
                              job.jqPriority === "critical" ? "text-red-400" :
                              job.jqPriority === "high" ? "text-orange-400" :
                              job.jqPriority === "normal" ? "text-blue-400" : "text-zinc-400"
                            }>
                              {job.jqPriority}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={JOB_STATUS_COLORS[job.jqStatus] || ""}>
                              {job.jqStatus}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{job.workerHost || "—"}</TableCell>
                          <TableCell className="text-xs">{formatDuration(job.durationMs)}</TableCell>
                          <TableCell>
                            {job.fipsCompliant ? (
                              <ShieldCheck className="w-4 h-4 text-green-400" />
                            ) : (
                              <AlertTriangle className="w-4 h-4 text-red-400" />
                            )}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {timeAgo(job.createdAt)}
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* ─── FIPS Compliance Tab ─────────────────────────────────── */}
          <TabsContent value="fips" className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                FIPS 140-3 Compliance Status
              </h2>
              <Button
                variant="outline"
                size="sm"
                onClick={() => complianceCheckMut.mutate()}
                disabled={complianceCheckMut.isPending}
              >
                <Shield className="w-4 h-4 mr-1" />
                Run Compliance Check
              </Button>
            </div>

            {complianceCheckMut.data && (
              <Card className={`border ${complianceCheckMut.data.overallCompliant ? "border-green-500/40 bg-green-500/5" : "border-red-500/40 bg-red-500/5"}`}>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-4">
                    {complianceCheckMut.data.overallCompliant ? (
                      <CheckCircle2 className="w-5 h-5 text-green-400" />
                    ) : (
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                    )}
                    <span className="font-semibold">
                      {complianceCheckMut.data.overallCompliant ? "All Checks Passed" : "Compliance Issues Detected"}
                    </span>
                  </div>
                  <div className="space-y-2">
                    {complianceCheckMut.data.checks.map((check: any) => (
                      <div key={check.id} className="flex items-center gap-3 py-2 border-b border-border/30 last:border-0">
                        <div className="w-6">
                          {check.status === "pass" ? (
                            <CheckCircle2 className="w-4 h-4 text-green-400" />
                          ) : check.status === "fail" ? (
                            <XCircle className="w-4 h-4 text-red-400" />
                          ) : check.status === "warning" ? (
                            <AlertTriangle className="w-4 h-4 text-yellow-400" />
                          ) : (
                            <Clock className="w-4 h-4 text-zinc-400" />
                          )}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">{check.name}</span>
                            <Badge variant="outline" className="text-xs">{check.nistControl}</Badge>
                          </div>
                          <p className="text-xs text-muted-foreground">{check.details}</p>
                          {check.remediation && (
                            <p className="text-xs text-yellow-400 mt-1">Remediation: {check.remediation}</p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Key Rotation */}
            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Key className="w-4 h-4 text-amber-400" />
                  Key Rotation Schedules
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border/50">
                      <TableHead>Key Type</TableHead>
                      <TableHead>Rotation Interval</TableHead>
                      <TableHead>Last Rotated</TableHead>
                      <TableHead>Next Rotation</TableHead>
                      <TableHead>Auto-Rotate</TableHead>
                      <TableHead>Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {keyRotation?.schedules?.map((s: any) => {
                      const isOverdue = s.nextRotation < Date.now();
                      return (
                        <TableRow key={s.keyType} className="border-border/30">
                          <TableCell className="font-medium">{s.keyType}</TableCell>
                          <TableCell>{s.rotationIntervalDays} days</TableCell>
                          <TableCell className="text-xs">{new Date(s.lastRotated).toLocaleDateString()}</TableCell>
                          <TableCell className="text-xs">{new Date(s.nextRotation).toLocaleDateString()}</TableCell>
                          <TableCell>
                            {s.autoRotate ? (
                              <Badge variant="outline" className="bg-green-500/10 text-green-400">Auto</Badge>
                            ) : (
                              <Badge variant="outline" className="bg-amber-500/10 text-amber-400">Manual</Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={isOverdue ? "bg-red-500/20 text-red-300" : "bg-green-500/20 text-green-300"}>
                              {isOverdue ? "OVERDUE" : "Current"}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      );
                    }) || (
                      <TableRow>
                        <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                          Loading key rotation data...
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* ─── Infrastructure Tab ──────────────────────────────────── */}
          <TabsContent value="infra" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* VPC Config */}
              <Card className="bg-card/50 border-border/50">
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Network className="w-4 h-4 text-blue-400" />
                    VPC Configuration
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <span className="text-muted-foreground">Name:</span>
                    <span className="font-mono">{infraStatus?.vpc?.name || "—"}</span>
                    <span className="text-muted-foreground">IP Range:</span>
                    <span className="font-mono">{infraStatus?.vpc?.ipRange || "—"}</span>
                    <span className="text-muted-foreground">Region:</span>
                    <span>{infraStatus?.vpc?.region || "—"}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{infraStatus?.vpc?.description}</p>
                </CardContent>
              </Card>

              {/* SSH Hardening */}
              <Card className="bg-card/50 border-border/50">
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Lock className="w-4 h-4 text-emerald-400" />
                    SSH Hardening
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <span className="text-muted-foreground">FIPS Algorithms:</span>
                    <Badge variant="outline" className={infraStatus?.sshHardening?.fipsAlgorithms ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"}>
                      {infraStatus?.sshHardening?.fipsAlgorithms ? "Enabled" : "Disabled"}
                    </Badge>
                    <span className="text-muted-foreground">Password Auth:</span>
                    <Badge variant="outline" className={!infraStatus?.sshHardening?.passwordAuth ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"}>
                      {infraStatus?.sshHardening?.passwordAuth ? "Enabled (RISK)" : "Disabled"}
                    </Badge>
                    <span className="text-muted-foreground">VPC-Only Access:</span>
                    <Badge variant="outline" className={infraStatus?.sshHardening?.vpcOnly ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"}>
                      {infraStatus?.sshHardening?.vpcOnly ? "Enforced" : "Not Enforced"}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Firewall Rules */}
            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Shield className="w-4 h-4 text-orange-400" />
                  Firewall Configurations
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border/50">
                      <TableHead>Service</TableHead>
                      <TableHead>Firewall Name</TableHead>
                      <TableHead>Inbound Rules</TableHead>
                      <TableHead>Outbound Rules</TableHead>
                      <TableHead>Public Inbound</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {infraStatus?.firewalls && Object.entries(infraStatus.firewalls).map(([key, fw]: [string, any]) => (
                      <TableRow key={key} className="border-border/30">
                        <TableCell className="font-medium capitalize">{key.replace(/([A-Z])/g, " $1").trim()}</TableCell>
                        <TableCell className="font-mono text-xs">{fw.name}</TableCell>
                        <TableCell>{fw.inboundRules}</TableCell>
                        <TableCell>{fw.outboundRules}</TableCell>
                        <TableCell>
                          {fw.publicInbound ? (
                            <Badge variant="outline" className="bg-red-500/20 text-red-300">
                              <AlertTriangle className="w-3 h-3 mr-1" /> EXPOSED
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="bg-green-500/20 text-green-300">
                              <Lock className="w-3 h-3 mr-1" /> BLOCKED
                            </Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            {/* NIST Controls */}
            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  NIST SP 800-53 Controls Addressed
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {infraStatus?.nistControls?.map((ctrl: string) => (
                    <Badge key={ctrl} variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                      {ctrl}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
