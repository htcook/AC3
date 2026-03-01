import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Search, AlertTriangle, Globe, ArrowRight, Database, Eye,
  FileText, Shield, Bug, Fingerprint, Radio
} from "lucide-react";

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  };
  return (
    <span className={`text-[9px] font-display tracking-widest px-2 py-0.5 rounded border ${colors[severity] || colors.info}`}>
      {severity.toUpperCase()}
    </span>
  );
}

export default function AnalystHome() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display tracking-wider font-bold">ANALYST DASHBOARD</h1>
        <p className="text-sm text-muted-foreground mt-1">Threat intelligence, vulnerability analysis, and OSINT research tools</p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "ACTIVE CVES", value: "1,247", icon: Bug, color: "bg-red-500/80" },
          { label: "THREAT ACTORS", value: "34", icon: Fingerprint, color: "bg-purple-500/80" },
          { label: "IOCs TRACKED", value: "8,912", icon: Eye, color: "bg-blue-500/80" },
          { label: "INTEL FEEDS", value: "12", icon: Radio, color: "bg-emerald-500/80" },
        ].map((stat) => (
          <Card key={stat.label}>
            <CardContent className="p-4">
              <div className={`w-8 h-8 rounded ${stat.color} flex items-center justify-center mb-2`}>
                <stat.icon className="w-4 h-4 text-white" />
              </div>
              <p className="text-2xl font-display font-bold">{stat.value}</p>
              <p className="text-[10px] font-display tracking-widest text-muted-foreground mt-1">{stat.label}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Threat Intel Feed + Vuln Triage */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-400" /> THREAT INTELLIGENCE FEED
              </CardTitle>
              <Link href="/threat-intel">
                <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                  VIEW ALL <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            {[
              { source: "CIRCL", title: "APT29 targeting cloud infrastructure with new backdoor", time: "12 min ago", severity: "critical" },
              { source: "AbuseIPDB", title: "Mass exploitation of CVE-2024-21762 (FortiOS)", time: "1 hr ago", severity: "high" },
              { source: "AlienVault", title: "New Lazarus Group campaign targeting DeFi platforms", time: "2 hrs ago", severity: "high" },
              { source: "MISP", title: "Updated IOCs for BlackCat/ALPHV ransomware variants", time: "3 hrs ago", severity: "medium" },
              { source: "SecurityTrails", title: "Suspicious DNS changes detected for monitored domains", time: "5 hrs ago", severity: "medium" },
            ].map((item, i) => (
              <div key={i} className="p-3 bg-secondary/30 rounded-lg hover:bg-secondary/50 transition-colors cursor-pointer">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[9px] font-display tracking-widest text-primary/70">{item.source}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-[9px] text-muted-foreground">{item.time}</span>
                    <SeverityBadge severity={item.severity} />
                  </div>
                </div>
                <p className="text-xs">{item.title}</p>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" /> VULNERABILITY TRIAGE
              </CardTitle>
              <Link href="/vuln-feeds">
                <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                  FULL LIST <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            {[
              { cve: "CVE-2024-21762", product: "FortiOS SSL VPN", cvss: 9.8, status: "exploited", affected: 3 },
              { cve: "CVE-2024-3400", product: "Palo Alto PAN-OS", cvss: 10.0, status: "exploited", affected: 1 },
              { cve: "CVE-2024-1709", product: "ConnectWise ScreenConnect", cvss: 10.0, status: "patched", affected: 0 },
              { cve: "CVE-2024-27198", product: "JetBrains TeamCity", cvss: 9.8, status: "unpatched", affected: 2 },
              { cve: "CVE-2024-20353", product: "Cisco ASA/FTD", cvss: 8.6, status: "mitigated", affected: 4 },
            ].map((vuln) => (
              <div key={vuln.cve} className="p-3 bg-secondary/30 rounded-lg">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-display tracking-wider font-medium text-red-400">{vuln.cve}</span>
                  <span className={`text-[9px] font-display tracking-widest px-2 py-0.5 rounded-full ${
                    vuln.status === "exploited" ? "bg-red-500/20 text-red-400" :
                    vuln.status === "unpatched" ? "bg-amber-500/20 text-amber-400" :
                    vuln.status === "patched" ? "bg-emerald-500/20 text-emerald-400" : "bg-blue-500/20 text-blue-400"
                  }`}>{vuln.status.toUpperCase()}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] text-muted-foreground">{vuln.product}</span>
                  <div className="flex items-center gap-3">
                    <span className="text-[10px]">CVSS: <span className={vuln.cvss >= 9 ? "text-red-400" : "text-amber-400"}>{vuln.cvss}</span></span>
                    <span className="text-[10px] text-muted-foreground">{vuln.affected} affected</span>
                  </div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Quick Research Tools */}
      <div>
        <h2 className="text-sm font-display tracking-widest text-muted-foreground mb-3">RESEARCH TOOLS</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {[
            { href: "/osint", icon: Search, label: "OSINT TOOLKIT", desc: "Domain, IP, email, and social media recon", color: "bg-blue-500/80" },
            { href: "/shodan", icon: Globe, label: "SHODAN SEARCH", desc: "Internet-wide device and service discovery", color: "bg-red-500/80" },
            { href: "/dehashed", icon: Database, label: "DEHASHED", desc: "Breach data and credential exposure search", color: "bg-purple-500/80" },
            { href: "/threat-intel", icon: Eye, label: "THREAT INTEL", desc: "APT tracking, IOCs, and campaign analysis", color: "bg-amber-500/80" },
            { href: "/vuln-feeds", icon: Bug, label: "VULN FEEDS", desc: "CVE monitoring with CARVER scoring", color: "bg-orange-500/80" },
            { href: "/export-center", icon: FileText, label: "EXPORT CENTER", desc: "Generate reports in CSV/PDF format", color: "bg-emerald-500/80" },
          ].map((tool) => (
            <Link key={tool.href} href={tool.href}>
              <Card className="group cursor-pointer hover:border-primary/30 transition-all duration-200 hover:shadow-lg hover:shadow-primary/5">
                <CardContent className="p-4 flex items-center gap-4">
                  <div className={`w-10 h-10 rounded-lg ${tool.color} flex items-center justify-center shrink-0`}>
                    <tool.icon className="w-5 h-5 text-white" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-display tracking-wider font-medium">{tool.label}</p>
                    <p className="text-xs text-muted-foreground">{tool.desc}</p>
                  </div>
                  <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors shrink-0" />
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
