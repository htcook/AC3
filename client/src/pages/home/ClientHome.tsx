import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Shield, AlertTriangle, CheckCircle2, ArrowRight, FileText,
  Download, Clock, BarChart3, TrendingDown
} from "lucide-react";

export default function ClientHome() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display tracking-wider font-bold">ASSESSMENT PORTAL</h1>
        <p className="text-sm text-muted-foreground mt-1">View your security assessment results, findings, and reports</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "TOTAL FINDINGS", value: "47", icon: AlertTriangle, color: "bg-amber-500/80" },
          { label: "CRITICAL", value: "6", icon: Shield, color: "bg-red-500/80" },
          { label: "REMEDIATED", value: "31", icon: CheckCircle2, color: "bg-emerald-500/80" },
          { label: "REPORTS READY", value: "3", icon: FileText, color: "bg-blue-500/80" },
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

      {/* Findings Breakdown + Remediation Progress */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-primary" /> FINDINGS BY SEVERITY
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {[
              { severity: "Critical", count: 6, total: 47, color: "bg-red-500", remediated: 4 },
              { severity: "High", count: 14, total: 47, color: "bg-orange-500", remediated: 10 },
              { severity: "Medium", count: 18, total: 47, color: "bg-amber-500", remediated: 12 },
              { severity: "Low", count: 7, total: 47, color: "bg-blue-500", remediated: 5 },
              { severity: "Info", count: 2, total: 47, color: "bg-gray-500", remediated: 0 },
            ].map((item) => (
              <div key={item.severity}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-display tracking-wider">{item.severity}</span>
                  <span className="text-[10px] text-muted-foreground">{item.remediated}/{item.count} remediated</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 bg-secondary rounded-full h-2">
                    <div className={`h-full rounded-full ${item.color}`} style={{ width: `${(item.count / item.total) * 100}%` }} />
                  </div>
                  <span className="text-xs font-display w-6 text-right">{item.count}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
              <TrendingDown className="w-4 h-4 text-emerald-400" /> REMEDIATION PROGRESS
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-center mb-4">
              <div className="relative w-32 h-32">
                <svg className="w-full h-full -rotate-90" viewBox="0 0 140 140">
                  <circle cx="70" cy="70" r="60" fill="none" stroke="currentColor" className="text-secondary" strokeWidth="10" />
                  <circle cx="70" cy="70" r="60" fill="none" stroke="currentColor" className="text-emerald-500" strokeWidth="10"
                    strokeDasharray={`${2 * Math.PI * 60}`} strokeDashoffset={`${2 * Math.PI * 60 * (1 - 31/47)}`}
                    strokeLinecap="round" style={{ transition: "stroke-dashoffset 1s ease" }} />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-2xl font-display font-bold text-emerald-400">66%</span>
                  <span className="text-[9px] font-display tracking-widest text-muted-foreground">REMEDIATED</span>
                </div>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="p-2 bg-secondary/30 rounded">
                <p className="text-lg font-display font-bold">31</p>
                <p className="text-[9px] font-display tracking-widest text-emerald-400">FIXED</p>
              </div>
              <div className="p-2 bg-secondary/30 rounded">
                <p className="text-lg font-display font-bold">12</p>
                <p className="text-[9px] font-display tracking-widest text-amber-400">IN PROGRESS</p>
              </div>
              <div className="p-2 bg-secondary/30 rounded">
                <p className="text-lg font-display font-bold">4</p>
                <p className="text-[9px] font-display tracking-widest text-red-400">OPEN</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Available Reports */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
              <FileText className="w-4 h-4 text-blue-400" /> AVAILABLE REPORTS
            </CardTitle>
            <Link href="/export-center">
              <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                EXPORT CENTER <ArrowRight className="w-3 h-3 ml-1" />
              </Button>
            </Link>
          </div>
        </CardHeader>
        <CardContent className="space-y-2">
          {[
            { name: "External Penetration Test Report", date: "Feb 28, 2026", type: "PDF", pages: 42 },
            { name: "Vulnerability Assessment Summary", date: "Feb 25, 2026", type: "PDF", pages: 18 },
            { name: "Executive Risk Briefing", date: "Feb 20, 2026", type: "PDF", pages: 8 },
          ].map((report) => (
            <div key={report.name} className="flex items-center justify-between p-3 bg-secondary/30 rounded-lg hover:bg-secondary/50 transition-colors">
              <div className="flex items-center gap-3">
                <FileText className="w-5 h-5 text-blue-400 shrink-0" />
                <div>
                  <p className="text-xs font-display tracking-wider">{report.name}</p>
                  <p className="text-[10px] text-muted-foreground">{report.date} · {report.pages} pages</p>
                </div>
              </div>
              <Button variant="outline" size="sm" className="text-[10px] font-display tracking-wider h-7">
                <Download className="w-3 h-3 mr-1" /> {report.type}
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Timeline */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
            <Clock className="w-4 h-4 text-muted-foreground" /> ASSESSMENT TIMELINE
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[
              { date: "Feb 10", event: "Engagement kickoff meeting", status: "completed" },
              { date: "Feb 12-20", event: "External penetration testing", status: "completed" },
              { date: "Feb 21-25", event: "Internal network assessment", status: "completed" },
              { date: "Feb 26-28", event: "Report preparation and review", status: "completed" },
              { date: "Mar 3", event: "Findings presentation", status: "upcoming" },
              { date: "Mar 10", event: "Remediation verification retest", status: "upcoming" },
            ].map((item, i) => (
              <div key={i} className="flex items-center gap-3">
                <div className={`w-3 h-3 rounded-full shrink-0 border-2 ${
                  item.status === "completed" ? "bg-emerald-500 border-emerald-500" : "bg-transparent border-muted-foreground"
                }`} />
                <span className="text-[10px] font-display tracking-wider text-muted-foreground w-20 shrink-0">{item.date}</span>
                <span className="text-xs">{item.event}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
