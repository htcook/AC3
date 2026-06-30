// @ts-nocheck
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  ArrowLeft, Shield, Target, AlertTriangle, Brain, Globe, Server,
  ChevronDown, ChevronUp, Crosshair, Zap, FileText, ExternalLink,
  Activity, Lock, Eye, Network, Loader2, BarChart3, Bug, Skull, Database, Cpu,
  TrendingUp, Fingerprint, Radar, Info, Search, Radio, Scan, Flag, Undo2, MessageSquare,
  Download, FlaskConical, Mail, ShieldAlert, ShieldCheck, ShieldX, CheckCircle2, XCircle, RefreshCw,
  Layers, Play, Pause, Settings2, GitBranch, Link2, Users, Hash, Clock, Unplug, Wifi,
  Workflow, Lightbulb, Route, Telescope, ShieldQuestion, ArrowRightLeft, KeyRound,
  Box, ClipboardCheck, PackageSearch, GitCompareArrows
} from "lucide-react";

export default function ChangeDetectionTab({ scanId }: { scanId: number }) {
  const { data, isLoading, error } = trpc.domainIntel.detectChanges.useQuery({ currentScanId: scanId });

  if (isLoading) return (
    <Card><CardContent className="flex items-center justify-center py-16">
      <Loader2 className="w-6 h-6 animate-spin text-cyan-400 mr-3" />
      <span className="text-muted-foreground">Comparing against previous scan...</span>
    </CardContent></Card>
  );

  if (error) return (
    <Card><CardContent className="py-8 text-center">
      <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto mb-2" />
      <p className="text-sm text-muted-foreground">{error.message}</p>
    </CardContent></Card>
  );

  if (!data || !data.hasHistory) return (
    <Card><CardContent className="flex flex-col items-center justify-center py-16 text-center">
      <GitBranch className="w-12 h-12 text-muted-foreground/40 mb-4" />
      <h3 className="text-lg font-medium mb-2">No Previous Scan Available</h3>
      <p className="text-sm text-muted-foreground max-w-md">
        Run another scan of the same domain to enable change detection. The engine will compare subdomains, IPs, ports, and technologies between scans to identify infrastructure changes.
      </p>
    </CardContent></Card>
  );

  const d = data as any;
  const summary = d.summary;
  const newSubs = d.newSubdomains || [];
  const removedSubs = d.removedSubdomains || [];
  const ipChanges = d.ipChanges || [];
  const portChanges = d.portChanges || [];
  const techChanges = d.techChanges || [];
  const alerts = d.securityAlerts || [];

  const totalChanges = newSubs.length + removedSubs.length + ipChanges.length + portChanges.length + techChanges.length;

  return (
    <div className="space-y-4">
      {/* Page Purpose */}
      <p className="text-sm text-muted-foreground">
        Compares the current scan against the most recent previous scan of the same domain to identify new subdomains, removed assets, IP changes, port changes, and technology drift.
      </p>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <Card className="bg-emerald-500/10 border-emerald-500/30">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-emerald-400">{newSubs.length}</div>
            <div className="text-[11px] text-muted-foreground">New Subdomains</div>
          </CardContent>
        </Card>
        <Card className="bg-red-500/10 border-red-500/30">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-red-400">{removedSubs.length}</div>
            <div className="text-[11px] text-muted-foreground">Removed</div>
          </CardContent>
        </Card>
        <Card className="bg-amber-500/10 border-amber-500/30">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-amber-400">{ipChanges.length}</div>
            <div className="text-[11px] text-muted-foreground">IP Changes</div>
          </CardContent>
        </Card>
        <Card className="bg-blue-500/10 border-blue-500/30">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-blue-400">{portChanges.length}</div>
            <div className="text-[11px] text-muted-foreground">Port Changes</div>
          </CardContent>
        </Card>
        <Card className="bg-purple-500/10 border-purple-500/30">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-purple-400">{techChanges.length}</div>
            <div className="text-[11px] text-muted-foreground">Tech Changes</div>
          </CardContent>
        </Card>
        <Card className={alerts.length > 0 ? "bg-red-500/10 border-red-500/30" : "bg-muted/30 border-border/50"}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold ${alerts.length > 0 ? 'text-red-400' : 'text-muted-foreground'}`}>{alerts.length}</div>
            <div className="text-[11px] text-muted-foreground">Security Alerts</div>
          </CardContent>
        </Card>
      </div>

      {/* Security Alerts */}
      {alerts.length > 0 && (
        <Card className="border-red-500/40">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              Security Alerts
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {alerts.map((alert: any, i: number) => (
              <div key={i} className={`p-3 rounded-lg border ${
                alert.severity === 'critical' ? 'bg-red-500/10 border-red-500/40' :
                alert.severity === 'high' ? 'bg-orange-500/10 border-orange-500/40' :
                'bg-amber-500/10 border-amber-500/40'
              }`}>
                <div className="flex items-center gap-2 mb-1">
                  <Badge variant="outline" className={
                    alert.severity === 'critical' ? 'text-red-400 border-red-500/40' :
                    alert.severity === 'high' ? 'text-orange-400 border-orange-500/40' :
                    'text-amber-400 border-amber-500/40'
                  }>{alert.severity}</Badge>
                  <span className="text-sm font-medium">{alert.type?.replace(/_/g, ' ')}</span>
                </div>
                <p className="text-sm text-muted-foreground">{alert.description}</p>
                {alert.subdomain && <p className="text-xs text-cyan-400 mt-1 font-mono">{alert.subdomain}</p>}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {totalChanges === 0 && (
        <Card className="bg-emerald-500/5 border-emerald-500/30">
          <CardContent className="flex items-center justify-center py-8">
            <ShieldCheck className="w-6 h-6 text-emerald-400 mr-3" />
            <span className="text-emerald-300">No infrastructure changes detected between scans.</span>
          </CardContent>
        </Card>
      )}

      {/* New Subdomains */}
      {newSubs.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-emerald-400" />
              New Subdomains ({newSubs.length})
            </CardTitle>
            <CardDescription>Subdomains discovered in the current scan that were not present in the previous scan.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-border/50 text-muted-foreground text-left">
                  <th className="pb-2 pr-4">Subdomain</th>
                  <th className="pb-2 pr-4">IP</th>
                  <th className="pb-2 pr-4">Source</th>
                  <th className="pb-2">Risk</th>
                </tr></thead>
                <tbody>
                  {newSubs.map((s: any, i: number) => (
                    <tr key={i} className="border-b border-border/20">
                      <td className="py-2 pr-4 font-mono text-xs text-cyan-400">{s.subdomain}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{s.ip || '—'}</td>
                      <td className="py-2 pr-4"><Badge variant="outline" className="text-[10px]">{s.source || 'scan'}</Badge></td>
                      <td className="py-2">
                        {s.riskIndicators?.length > 0 ? (
                          <Badge variant="outline" className="text-amber-400 border-amber-500/40 text-[10px]">
                            {s.riskIndicators.length} risk{s.riskIndicators.length > 1 ? 's' : ''}
                          </Badge>
                        ) : <span className="text-muted-foreground text-xs">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Removed Subdomains */}
      {removedSubs.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <XCircle className="w-4 h-4 text-red-400" />
              Removed Subdomains ({removedSubs.length})
            </CardTitle>
            <CardDescription>Subdomains present in the previous scan that are no longer detected. May indicate decommissioned infrastructure or DNS changes.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-border/50 text-muted-foreground text-left">
                  <th className="pb-2 pr-4">Subdomain</th>
                  <th className="pb-2 pr-4">Previous IP</th>
                  <th className="pb-2">Risk</th>
                </tr></thead>
                <tbody>
                  {removedSubs.map((s: any, i: number) => (
                    <tr key={i} className="border-b border-border/20">
                      <td className="py-2 pr-4 font-mono text-xs text-red-400 line-through">{s.subdomain}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{s.previousIp || '—'}</td>
                      <td className="py-2">
                        {s.riskIndicators?.length > 0 ? (
                          <Badge variant="outline" className="text-amber-400 border-amber-500/40 text-[10px]">
                            {s.riskIndicators.length} risk{s.riskIndicators.length > 1 ? 's' : ''}
                          </Badge>
                        ) : <span className="text-muted-foreground text-xs">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* IP Changes */}
      {ipChanges.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Network className="w-4 h-4 text-amber-400" />
              IP Address Changes ({ipChanges.length})
            </CardTitle>
            <CardDescription>Subdomains whose resolved IP addresses changed between scans. May indicate infrastructure migration or DNS hijacking.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-border/50 text-muted-foreground text-left">
                  <th className="pb-2 pr-4">Subdomain</th>
                  <th className="pb-2 pr-4">Previous IP</th>
                  <th className="pb-2 pr-4">Current IP</th>
                  <th className="pb-2">ASN Change</th>
                </tr></thead>
                <tbody>
                  {ipChanges.map((c: any, i: number) => (
                    <tr key={i} className="border-b border-border/20">
                      <td className="py-2 pr-4 font-mono text-xs text-cyan-400">{c.subdomain}</td>
                      <td className="py-2 pr-4 font-mono text-xs text-red-400">{c.previousIp}</td>
                      <td className="py-2 pr-4 font-mono text-xs text-emerald-400">{c.currentIp}</td>
                      <td className="py-2">
                        {c.asnChanged ? (
                          <Badge variant="outline" className="text-red-400 border-red-500/40 text-[10px]">ASN Changed</Badge>
                        ) : <span className="text-muted-foreground text-xs">Same ASN</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Port Changes */}
      {portChanges.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Unplug className="w-4 h-4 text-blue-400" />
              Port Changes ({portChanges.length})
            </CardTitle>
            <CardDescription>New ports opened or previously open ports now closed on discovered assets.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-border/50 text-muted-foreground text-left">
                  <th className="pb-2 pr-4">Subdomain</th>
                  <th className="pb-2 pr-4">New Ports</th>
                  <th className="pb-2 pr-4">Closed Ports</th>
                  <th className="pb-2">Service Changes</th>
                </tr></thead>
                <tbody>
                  {portChanges.map((c: any, i: number) => (
                    <tr key={i} className="border-b border-border/20">
                      <td className="py-2 pr-4 font-mono text-xs text-cyan-400">{c.subdomain}</td>
                      <td className="py-2 pr-4">
                        {c.newPorts?.length > 0 ? c.newPorts.map((p: any, j: number) => (
                          <Badge key={j} variant="outline" className="text-emerald-400 border-emerald-500/40 text-[10px] mr-1 mb-1">
                            {p.port}/{p.transport} {p.product ? `(${p.product})` : ''}
                          </Badge>
                        )) : <span className="text-muted-foreground text-xs">—</span>}
                      </td>
                      <td className="py-2 pr-4">
                        {c.closedPorts?.length > 0 ? c.closedPorts.map((p: any, j: number) => (
                          <Badge key={j} variant="outline" className="text-red-400 border-red-500/40 text-[10px] mr-1 mb-1">
                            {p.port}/{p.transport}
                          </Badge>
                        )) : <span className="text-muted-foreground text-xs">—</span>}
                      </td>
                      <td className="py-2">
                        {c.serviceChanges?.length > 0 ? c.serviceChanges.map((s: any, j: number) => (
                          <div key={j} className="text-xs text-muted-foreground">
                            Port {s.port}: <span className="text-red-400">{s.previousService}</span> → <span className="text-emerald-400">{s.currentService}</span>
                          </div>
                        )) : <span className="text-muted-foreground text-xs">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Technology Changes */}
      {techChanges.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Cpu className="w-4 h-4 text-purple-400" />
              Technology Changes ({techChanges.length})
            </CardTitle>
            <CardDescription>New technologies detected or previously detected technologies no longer present on assets.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-border/50 text-muted-foreground text-left">
                  <th className="pb-2 pr-4">Asset</th>
                  <th className="pb-2 pr-4">New Technologies</th>
                  <th className="pb-2">Removed Technologies</th>
                </tr></thead>
                <tbody>
                  {techChanges.map((c: any, i: number) => (
                    <tr key={i} className="border-b border-border/20">
                      <td className="py-2 pr-4 font-mono text-xs text-cyan-400">{c.hostname}</td>
                      <td className="py-2 pr-4">
                        {c.addedTech?.length > 0 ? c.addedTech.map((t: string, j: number) => (
                          <Badge key={j} variant="outline" className="text-emerald-400 border-emerald-500/40 text-[10px] mr-1 mb-1">+ {t}</Badge>
                        )) : <span className="text-muted-foreground text-xs">—</span>}
                      </td>
                      <td className="py-2">
                        {c.removedTech?.length > 0 ? c.removedTech.map((t: string, j: number) => (
                          <Badge key={j} variant="outline" className="text-red-400 border-red-500/40 text-[10px] mr-1 mb-1">- {t}</Badge>
                        )) : <span className="text-muted-foreground text-xs">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan Comparison Metadata */}
      <Card className="bg-muted/20">
        <CardContent className="p-3">
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span>Current Scan: #{d.currentScanId}</span>
            <span>Previous Scan: #{d.previousScanId}</span>
            <span>Domain: {d.domain}</span>
            {summary && <span>Scan Interval: {summary.daysBetweenScans} days</span>}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════
// Tech Vulns Tab — Technology Vulnerability CVE Cross-Reference
// ═══════════════════════════════════════════════════════════════════════════

