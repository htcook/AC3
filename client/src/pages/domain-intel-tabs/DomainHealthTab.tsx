// @ts-nocheck
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  HeartPulse, ShieldX, MailCheck, Stethoscope, Wifi, ListChecks,
  CheckCircle2, XCircle, AlertTriangle, Info, Globe,
  Server, Lock, Clock, Activity
} from "lucide-react";

const GRADE_COLORS: Record<string, string> = {
  A: "text-emerald-400 bg-emerald-500/20 border-emerald-500/40",
  B: "text-blue-400 bg-blue-500/20 border-blue-500/40",
  C: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40",
  D: "text-orange-400 bg-orange-500/20 border-orange-500/40",
  F: "text-red-400 bg-red-500/20 border-red-500/40",
};

const SEV_ICON: Record<string, any> = {
  critical: <XCircle className="h-4 w-4 text-red-400 shrink-0" />,
  warning: <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0" />,
  info: <Info className="h-4 w-4 text-blue-400 shrink-0" />,
};

function ScoreGauge({ score, grade, label, size = "lg" }: { score: number; grade: string; label: string; size?: "sm" | "lg" }) {
  const r = size === "lg" ? 55 : 30, sw = size === "lg" ? 7 : 4;
  const c = 2 * Math.PI * r, p = (score / 100) * c;
  const col = grade === "A" ? "#22c55e" : grade === "B" ? "#3b82f6" : grade === "C" ? "#eab308" : grade === "D" ? "#f97316" : "#ef4444";
  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative inline-flex items-center justify-center">
        <svg width={(r + sw) * 2} height={(r + sw) * 2} className="-rotate-90">
          <circle cx={r + sw} cy={r + sw} r={r} fill="none" stroke="currentColor" strokeWidth={sw} className="text-muted/20" />
          <circle cx={r + sw} cy={r + sw} r={r} fill="none" stroke={col} strokeWidth={sw}
            strokeDasharray={c} strokeDashoffset={c - p} strokeLinecap="round" className="transition-all duration-1000" />
        </svg>
        <div className="absolute flex flex-col items-center">
          <span className={`font-bold ${size === "lg" ? "text-2xl" : "text-sm"}`} style={{ color: col }}>{grade}</span>
          <span className={`text-muted-foreground ${size === "lg" ? "text-xs" : "text-[10px]"}`}>{score}/100</span>
        </div>
      </div>
      <span className={`text-muted-foreground font-medium ${size === "lg" ? "text-xs" : "text-[10px]"}`}>{label}</span>
    </div>
  );
}

function ScoreBar({ label, score, grade, icon }: { label: string; score: number; grade: string; icon: React.ReactNode }) {
  const bg = grade === "A" ? "bg-emerald-500" : grade === "B" ? "bg-blue-500" : grade === "C" ? "bg-yellow-500" : grade === "D" ? "bg-orange-500" : "bg-red-500";
  const tc = grade === "A" ? "text-emerald-400" : grade === "B" ? "text-blue-400" : grade === "C" ? "text-yellow-400" : grade === "D" ? "text-orange-400" : "text-red-400";
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm">{icon}<span className="text-foreground/80">{label}</span></div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className={`${GRADE_COLORS[grade] || ""} text-xs px-1.5`}>{grade}</Badge>
          <span className={`text-sm font-mono font-medium ${tc}`}>{score}</span>
        </div>
      </div>
      <div className="h-1.5 bg-muted/30 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-700 ${bg}`} style={{ width: `${score}%` }} />
      </div>
    </div>
  );
}

function Issues({ issues, category }: { issues: any[]; category?: string }) {
  const list = category ? issues.filter((i: any) => i.category === category) : issues;
  if (!list.length) return (
    <div className="flex items-center gap-2 text-emerald-400 text-sm p-3 bg-emerald-500/10 rounded-lg border border-emerald-500/20">
      <CheckCircle2 className="h-4 w-4" /> No issues detected
    </div>
  );
  return (
    <div className="space-y-2">
      {list.map((issue: any, i: number) => (
        <div key={i} className="flex items-start gap-2.5 p-2.5 rounded-lg bg-muted/10 border border-border/50">
          {SEV_ICON[issue.severity] || SEV_ICON.info}
          <span className="text-sm text-foreground/90">{issue.message}</span>
        </div>
      ))}
    </div>
  );
}

function HealthOverview({ report }: { report: any }) {
  const c = report.categories;
  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">Comprehensive domain health assessment covering blacklist reputation, mail server configuration, DNS infrastructure, reverse DNS, and network connectivity. Equivalent to MXToolbox SuperTool diagnostics.</p>
      <Card className="bg-card/50 border-border/50"><CardContent className="pt-6">
        <div className="flex flex-col md:flex-row items-center gap-8">
          <ScoreGauge score={report.overallScore} grade={report.overallGrade} label="Overall Health" size="lg" />
          <div className="flex-1 grid grid-cols-3 sm:grid-cols-6 gap-4">
            <ScoreGauge score={c.blacklist.score} grade={c.blacklist.grade} label="Blacklist" size="sm" />
            <ScoreGauge score={c.mailServer.score} grade={c.mailServer.grade} label="Mail" size="sm" />
            <ScoreGauge score={c.dnsHealth.score} grade={c.dnsHealth.grade} label="DNS" size="sm" />
            <ScoreGauge score={c.reverseDs.score} grade={c.reverseDs.grade} label="rDNS" size="sm" />
            <ScoreGauge score={c.ipInfo.score} grade={c.ipInfo.grade} label="IP Info" size="sm" />
            <ScoreGauge score={c.connectivity.score} grade={c.connectivity.grade} label="Connect" size="sm" />
          </div>
        </div>
      </CardContent></Card>
      <Card className="bg-card/50 border-border/50">
        <CardHeader className="pb-3"><CardTitle className="text-base flex items-center gap-2"><Activity className="h-4 w-4 text-green-400" /> Category Breakdown</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <ScoreBar label="Blacklist / DNSBL" score={c.blacklist.score} grade={c.blacklist.grade} icon={<ShieldX className="h-4 w-4 text-red-400" />} />
          <ScoreBar label="Mail Server (SMTP)" score={c.mailServer.score} grade={c.mailServer.grade} icon={<MailCheck className="h-4 w-4 text-blue-400" />} />
          <ScoreBar label="DNS Health" score={c.dnsHealth.score} grade={c.dnsHealth.grade} icon={<Stethoscope className="h-4 w-4 text-purple-400" />} />
          <ScoreBar label="Reverse DNS (PTR)" score={c.reverseDs.score} grade={c.reverseDs.grade} icon={<Globe className="h-4 w-4 text-cyan-400" />} />
          <ScoreBar label="IP Block Info" score={c.ipInfo.score} grade={c.ipInfo.grade} icon={<Server className="h-4 w-4 text-amber-400" />} />
          <ScoreBar label="TCP Connectivity" score={c.connectivity.score} grade={c.connectivity.grade} icon={<Wifi className="h-4 w-4 text-green-400" />} />
        </CardContent>
      </Card>
      <Card className="bg-card/50 border-border/50">
        <CardHeader className="pb-3"><CardTitle className="text-base flex items-center gap-2"><AlertTriangle className="h-4 w-4 text-yellow-400" /> Issues ({report.issues.length})</CardTitle></CardHeader>
        <CardContent><Issues issues={[...report.issues].sort((a: any, b: any) => ({ critical: 0, warning: 1, info: 2 }[a.severity] ?? 3) - ({ critical: 0, warning: 1, info: 2 }[b.severity] ?? 3))} /></CardContent>
      </Card>
      <div className="text-xs text-muted-foreground flex items-center gap-2"><Clock className="h-3 w-3" />Scan completed in {(report.durationMs / 1000).toFixed(1)}s on {new Date(report.timestamp).toLocaleString()}</div>
    </div>
  );
}

function BlacklistTab({ report }: { report: any }) {
  const bl = report.categories.blacklist.details;
  if (!bl) return <div className="text-sm text-muted-foreground p-4">No blacklist data — domain could not be resolved to an IP.</div>;
  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">DNS-based Blackhole List (DNSBL) check across {bl.totalChecked} blacklists. Being listed on major blacklists can cause email delivery failures and reputation damage.</p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-card/50 border-border/50"><CardContent className="pt-5 text-center"><div className="text-3xl font-bold text-foreground">{bl.totalChecked}</div><div className="text-xs text-muted-foreground mt-1">Lists Checked</div></CardContent></Card>
        <Card className={`border-border/50 ${bl.listed.length > 0 ? "bg-red-500/5" : "bg-emerald-500/5"}`}><CardContent className="pt-5 text-center"><div className={`text-3xl font-bold ${bl.listed.length > 0 ? "text-red-400" : "text-emerald-400"}`}>{bl.listed.length}</div><div className="text-xs text-muted-foreground mt-1">Listed On</div></CardContent></Card>
        <Card className="bg-emerald-500/5 border-border/50"><CardContent className="pt-5 text-center"><div className="text-3xl font-bold text-emerald-400">{bl.clean.length}</div><div className="text-xs text-muted-foreground mt-1">Clean</div></CardContent></Card>
      </div>
      {bl.listed.length > 0 ? (
        <Card className="bg-red-500/5 border-red-500/20">
          <CardHeader className="pb-3"><CardTitle className="text-base flex items-center gap-2 text-red-400"><ShieldX className="h-4 w-4" /> Blacklisted ({bl.listed.length})</CardTitle><CardDescription>IP {bl.ip} is listed on these DNS blacklists</CardDescription></CardHeader>
          <CardContent><div className="space-y-2">{bl.listed.map((e: any, i: number) => (
            <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-muted/10 border border-red-500/20">
              <div className="flex items-center gap-2"><XCircle className="h-4 w-4 text-red-400 shrink-0" /><span className="text-sm font-mono text-foreground/90">{e.zone}</span></div>
              <Badge variant="outline" className="text-red-400 bg-red-500/10 border-red-500/30 text-xs">{e.result.join(", ")}</Badge>
            </div>
          ))}</div></CardContent>
        </Card>
      ) : (
        <Card className="bg-emerald-500/5 border-emerald-500/20"><CardContent className="pt-6"><div className="flex items-center gap-3 text-emerald-400"><CheckCircle2 className="h-6 w-6" /><div><div className="font-medium">Clean — Not Blacklisted</div><div className="text-xs text-muted-foreground mt-0.5">IP {bl.ip} is not listed on any of the {bl.totalChecked} DNS blacklists.</div></div></div></CardContent></Card>
      )}
      <Issues issues={report.issues} category="blacklist" />
    </div>
  );
}

function MailServerTab({ report }: { report: any }) {
  const smtp = report.categories.mailServer.details || [];
  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">SMTP connectivity and configuration tests for all MX records. Verifies port 25 reachability, EHLO support, STARTTLS encryption, and server banner information.</p>
      {!smtp.length ? (
        <Card className="bg-red-500/5 border-red-500/20"><CardContent className="pt-6"><div className="flex items-center gap-3 text-red-400"><XCircle className="h-6 w-6" /><div><div className="font-medium">No MX Records Found</div><div className="text-xs text-muted-foreground mt-0.5">This domain has no MX records and cannot receive email.</div></div></div></CardContent></Card>
      ) : smtp.map((s: any, i: number) => (
        <Card key={i} className={`border-border/50 ${s.connected ? "bg-card/50" : "bg-red-500/5 border-red-500/20"}`}>
          <CardHeader className="pb-3"><CardTitle className="text-base flex items-center gap-2">
            {s.connected ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-red-400" />}
            {s.host}<Badge variant="outline" className="text-xs ml-auto">{s.latencyMs}ms</Badge>
          </CardTitle></CardHeader>
          <CardContent>{s.connected ? (
            <div className="space-y-3">
              {s.banner && <div className="text-xs font-mono text-muted-foreground bg-muted/20 p-2 rounded break-all">{s.banner}</div>}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="flex items-center gap-1.5 text-sm">
                  {s.supportsStartTls ? <Lock className="h-3.5 w-3.5 text-emerald-400" /> : <AlertTriangle className="h-3.5 w-3.5 text-yellow-400" />}
                  <span className={s.supportsStartTls ? "text-emerald-400" : "text-yellow-400"}>{s.supportsStartTls ? "STARTTLS" : "No TLS"}</span>
                </div>
                <div className="flex items-center gap-1.5 text-sm">
                  {s.supportsEhlo ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : <XCircle className="h-3.5 w-3.5 text-red-400" />}
                  <span>{s.supportsEhlo ? "EHLO OK" : "No EHLO"}</span>
                </div>
              </div>
              {s.ehloExtensions?.length > 0 && <div><div className="text-xs text-muted-foreground mb-1.5">EHLO Extensions:</div><div className="flex flex-wrap gap-1.5">{s.ehloExtensions.map((ext: string, j: number) => <Badge key={j} variant="outline" className="text-[10px] font-mono">{ext}</Badge>)}</div></div>}
            </div>
          ) : <div className="text-sm text-red-400">{s.error || "Connection failed"}</div>}</CardContent>
        </Card>
      ))}
      <Issues issues={report.issues} category="mailServer" />
    </div>
  );
}

function DnsHealthTab({ report }: { report: any }) {
  const dns = report.categories.dnsHealth.details;
  if (!dns) return <div className="text-sm text-muted-foreground p-4">DNS health data not available.</div>;
  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">DNS infrastructure health check covering nameserver consistency, SOA serial synchronization, zone transfer protection, and glue record validation.</p>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card className="bg-card/50 border-border/50"><CardContent className="pt-5 text-center"><div className="text-2xl font-bold text-foreground">{dns.nameservers.length}</div><div className="text-xs text-muted-foreground mt-1">Nameservers</div></CardContent></Card>
        <Card className={`border-border/50 ${dns.soaConsistent ? "bg-emerald-500/5" : "bg-red-500/5"}`}><CardContent className="pt-5 text-center">{dns.soaConsistent ? <CheckCircle2 className="h-5 w-5 text-emerald-400 mx-auto" /> : <XCircle className="h-5 w-5 text-red-400 mx-auto" />}<div className="text-xs text-muted-foreground mt-1.5">SOA Consistent</div></CardContent></Card>
        <Card className={`border-border/50 ${dns.nsConsistent ? "bg-emerald-500/5" : "bg-red-500/5"}`}><CardContent className="pt-5 text-center">{dns.nsConsistent ? <CheckCircle2 className="h-5 w-5 text-emerald-400 mx-auto" /> : <XCircle className="h-5 w-5 text-red-400 mx-auto" />}<div className="text-xs text-muted-foreground mt-1.5">NS Consistent</div></CardContent></Card>
        <Card className={`border-border/50 ${dns.zoneTransferBlocked ? "bg-emerald-500/5" : "bg-red-500/5"}`}><CardContent className="pt-5 text-center">{dns.zoneTransferBlocked ? <CheckCircle2 className="h-5 w-5 text-emerald-400 mx-auto" /> : <AlertTriangle className="h-5 w-5 text-yellow-400 mx-auto" />}<div className="text-xs text-muted-foreground mt-1.5">AXFR Blocked</div></CardContent></Card>
      </div>
      <Card className="bg-card/50 border-border/50">
        <CardHeader className="pb-3"><CardTitle className="text-base flex items-center gap-2"><Server className="h-4 w-4 text-purple-400" /> Nameservers</CardTitle></CardHeader>
        <CardContent><div className="space-y-1.5">{dns.nameservers.map((ns: string, i: number) => (
          <div key={i} className="flex items-center gap-2 p-2 rounded bg-muted/10 border border-border/30"><Globe className="h-3.5 w-3.5 text-muted-foreground shrink-0" /><span className="text-sm font-mono text-foreground/90">{ns}</span></div>
        ))}</div></CardContent>
      </Card>
      {dns.soaSerials && Object.keys(dns.soaSerials).length > 0 && (
        <Card className="bg-card/50 border-border/50">
          <CardHeader className="pb-3"><CardTitle className="text-base flex items-center gap-2"><Activity className="h-4 w-4 text-blue-400" /> SOA Serial Numbers</CardTitle><CardDescription>SOA serial numbers should match across all nameservers</CardDescription></CardHeader>
          <CardContent><div className="space-y-1.5">{Object.entries(dns.soaSerials).map(([ns, serial]: [string, any]) => (
            <div key={ns} className="flex items-center justify-between p-2 rounded bg-muted/10 border border-border/30"><span className="text-sm font-mono text-muted-foreground">{ns}</span><Badge variant="outline" className="font-mono text-xs">{String(serial)}</Badge></div>
          ))}</div></CardContent>
        </Card>
      )}
      <Issues issues={report.issues} category="dnsHealth" />
    </div>
  );
}

function ConnectivityTab({ report }: { report: any }) {
  const tcp = report.categories.connectivity.details || [];
  const ptr = report.categories.reverseDs.details || [];
  const ipInfo = report.categories.ipInfo.details || [];
  const PL: Record<number, string> = { 25: "SMTP", 80: "HTTP", 143: "IMAP", 443: "HTTPS", 587: "SMTP/TLS", 993: "IMAPS" };
  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">TCP port reachability, reverse DNS (PTR) records, and IP block information.</p>
      <Card className="bg-card/50 border-border/50">
        <CardHeader className="pb-3"><CardTitle className="text-base flex items-center gap-2"><Wifi className="h-4 w-4 text-green-400" /> TCP Port Reachability</CardTitle></CardHeader>
        <CardContent>{!tcp.length ? <div className="text-sm text-muted-foreground">No connectivity data.</div> : (
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">{tcp.map((t: any, i: number) => (
            <div key={i} className={`flex items-center gap-2.5 p-3 rounded-lg border ${t.connected ? "bg-emerald-500/5 border-emerald-500/20" : "bg-muted/10 border-border/30"}`}>
              {t.connected ? <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" /> : <XCircle className="h-4 w-4 text-muted-foreground shrink-0" />}
              <div><div className="text-sm font-medium">{PL[t.port] || `Port ${t.port}`}</div><div className="text-[10px] text-muted-foreground">:{t.port} — {t.connected ? `${t.latencyMs}ms` : "closed"}</div></div>
            </div>
          ))}</div>
        )}</CardContent>
      </Card>
      {ptr.length > 0 && (
        <Card className="bg-card/50 border-border/50">
          <CardHeader className="pb-3"><CardTitle className="text-base flex items-center gap-2"><Globe className="h-4 w-4 text-cyan-400" /> Reverse DNS (PTR)</CardTitle></CardHeader>
          <CardContent><div className="space-y-2">{ptr.map((p: any, i: number) => (
            <div key={i} className="flex items-start gap-2.5 p-2.5 rounded-lg bg-muted/10 border border-border/30">
              {p.hasPtrRecord ? (p.matchesForwardDns ? <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" /> : <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0 mt-0.5" />) : <XCircle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />}
              <div className="min-w-0"><div className="text-sm font-mono">{p.ip}</div>
                {p.hasPtrRecord ? <div className="text-xs text-muted-foreground mt-0.5">{p.hostnames.join(", ")} {p.matchesForwardDns ? "(FCrDNS OK)" : "(FCrDNS mismatch)"}</div> : <div className="text-xs text-red-400/80 mt-0.5">No PTR record{p.error ? ` — ${p.error}` : ""}</div>}
              </div>
            </div>
          ))}</div></CardContent>
        </Card>
      )}
      {ipInfo.length > 0 && ipInfo[0] && !ipInfo[0].error && (
        <Card className="bg-card/50 border-border/50">
          <CardHeader className="pb-3"><CardTitle className="text-base flex items-center gap-2"><Server className="h-4 w-4 text-amber-400" /> IP Block Info (RDAP)</CardTitle></CardHeader>
          <CardContent>{ipInfo.map((info: any, i: number) => (
            <div key={i} className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
              <div><span className="text-muted-foreground">IP:</span> <span className="font-mono">{info.ip}</span></div>
              {info.asn && <div><span className="text-muted-foreground">ASN:</span> <span className="font-mono">AS{info.asn}</span></div>}
              {info.asnName && <div><span className="text-muted-foreground">ASN Name:</span> {info.asnName}</div>}
              {info.organization && <div><span className="text-muted-foreground">Org:</span> {info.organization}</div>}
              {info.networkCidr && <div><span className="text-muted-foreground">Network:</span> <span className="font-mono">{info.networkCidr}</span></div>}
              {info.country && <div><span className="text-muted-foreground">Country:</span> {info.country}</div>}
            </div>
          ))}</CardContent>
        </Card>
      )}
      <Issues issues={report.issues} category="connectivity" />
      <Issues issues={report.issues} category="reverseDns" />
    </div>
  );
}

function AllChecksTab({ report }: { report: any }) {
  const c = report.categories;
  const sections = [
    { key: "blacklist", label: "Blacklist / DNSBL", icon: <ShieldX className="h-4 w-4 text-red-400" />, score: c.blacklist.score, grade: c.blacklist.grade },
    { key: "mailServer", label: "Mail Server (SMTP)", icon: <MailCheck className="h-4 w-4 text-blue-400" />, score: c.mailServer.score, grade: c.mailServer.grade },
    { key: "dnsHealth", label: "DNS Health", icon: <Stethoscope className="h-4 w-4 text-purple-400" />, score: c.dnsHealth.score, grade: c.dnsHealth.grade },
    { key: "reverseDns", label: "Reverse DNS (PTR)", icon: <Globe className="h-4 w-4 text-cyan-400" />, score: c.reverseDs.score, grade: c.reverseDs.grade },
    { key: "ipInfo", label: "IP Block Info", icon: <Server className="h-4 w-4 text-amber-400" />, score: c.ipInfo.score, grade: c.ipInfo.grade },
    { key: "connectivity", label: "TCP Connectivity", icon: <Wifi className="h-4 w-4 text-green-400" />, score: c.connectivity.score, grade: c.connectivity.grade },
  ];
  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">Complete view of all domain health checks with scores and issues grouped by category.</p>
      {sections.map(s => (
        <Card key={s.key} className="bg-card/50 border-border/50">
          <CardHeader className="pb-3"><div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">{s.icon} {s.label}</CardTitle>
            <div className="flex items-center gap-2"><Badge variant="outline" className={`${GRADE_COLORS[s.grade] || ""} text-xs`}>{s.grade}</Badge><span className="text-sm font-mono text-muted-foreground">{s.score}/100</span></div>
          </div></CardHeader>
          <CardContent><Issues issues={report.issues} category={s.key} /></CardContent>
        </Card>
      ))}
      <div className="text-xs text-muted-foreground flex items-center gap-2"><Clock className="h-3 w-3" />Full scan: {(report.durationMs / 1000).toFixed(1)}s — {report.domain} — {new Date(report.timestamp).toLocaleString()}</div>
    </div>
  );
}

export default function DomainHealthTab({ report, activeSubTab }: { report: any; activeSubTab: string }) {
  if (!report) return (
    <Card className="bg-card/50 border-border/50"><CardContent className="pt-6">
      <div className="flex flex-col items-center gap-3 text-muted-foreground py-8">
        <HeartPulse className="h-8 w-8 opacity-40" />
        <div className="text-center"><div className="font-medium">Domain Health Data Not Available</div><div className="text-xs mt-1">Run a new scan to generate domain health diagnostics.</div></div>
      </div>
    </CardContent></Card>
  );
  switch (activeSubTab) {
    case "health-overview": return <HealthOverview report={report} />;
    case "health-blacklist": return <BlacklistTab report={report} />;
    case "health-mail": return <MailServerTab report={report} />;
    case "health-dns": return <DnsHealthTab report={report} />;
    case "health-connectivity": return <ConnectivityTab report={report} />;
    case "health-all": return <AllChecksTab report={report} />;
    default: return <HealthOverview report={report} />;
  }
}
