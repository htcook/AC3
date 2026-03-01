import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Users, Calendar, ArrowRight, Target, Clock, CheckCircle2,
  AlertTriangle, Briefcase, BarChart3, GitBranch
} from "lucide-react";

export default function TeamLeadHome() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display tracking-wider font-bold">TEAM LEAD DASHBOARD</h1>
        <p className="text-sm text-muted-foreground mt-1">Engagement pipeline, team workload, and delivery tracking</p>
      </div>

      {/* Pipeline Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        {[
          { label: "PIPELINE", value: "8", sub: "engagements", color: "bg-blue-500/80", icon: Briefcase },
          { label: "IN PROGRESS", value: "3", sub: "active now", color: "bg-emerald-500/80", icon: GitBranch },
          { label: "REPORTING", value: "2", sub: "pending review", color: "bg-purple-500/80", icon: BarChart3 },
          { label: "OVERDUE", value: "1", sub: "needs attention", color: "bg-red-500/80", icon: AlertTriangle },
          { label: "TEAM SIZE", value: "6", sub: "operators", color: "bg-amber-500/80", icon: Users },
        ].map((stat) => (
          <Card key={stat.label}>
            <CardContent className="p-4">
              <div className={`w-8 h-8 rounded ${stat.color} flex items-center justify-center mb-2`}>
                <stat.icon className="w-4 h-4 text-white" />
              </div>
              <p className="text-2xl font-display font-bold">{stat.value}</p>
              <p className="text-[10px] font-display tracking-widest text-muted-foreground">{stat.label}</p>
              <p className="text-[9px] text-muted-foreground/60">{stat.sub}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Engagement Pipeline + Team Workload */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Target className="w-4 h-4 text-primary" /> ENGAGEMENT PIPELINE
              </CardTitle>
              <Link href="/engagements">
                <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                  MANAGE <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            {[
              { name: "Project Nightfall", client: "Acme Corp", phase: "Gaining Access", due: "Mar 15", status: "on-track", operator: "JD" },
              { name: "Red Team Q1", client: "TechStart Inc", phase: "Lateral Movement", due: "Mar 22", status: "on-track", operator: "SK" },
              { name: "Cloud Pentest", client: "FinServ LLC", phase: "Reconnaissance", due: "Mar 8", status: "at-risk", operator: "MR" },
              { name: "External Pentest", client: "HealthCo", phase: "Reporting", due: "Mar 5", status: "overdue", operator: "AL" },
              { name: "Wireless Assessment", client: "RetailMax", phase: "Planning", due: "Apr 1", status: "on-track", operator: "TK" },
            ].map((eng) => (
              <div key={eng.name} className="p-3 bg-secondary/30 rounded-lg">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <div className="w-7 h-7 rounded bg-primary/20 flex items-center justify-center text-[10px] font-display text-primary">{eng.operator}</div>
                    <div>
                      <p className="text-xs font-display tracking-wider font-medium">{eng.name}</p>
                      <p className="text-[10px] text-muted-foreground">{eng.client}</p>
                    </div>
                  </div>
                  <span className={`text-[9px] font-display tracking-widest px-2 py-0.5 rounded-full ${
                    eng.status === "on-track" ? "bg-emerald-500/20 text-emerald-400" :
                    eng.status === "at-risk" ? "bg-amber-500/20 text-amber-400" : "bg-red-500/20 text-red-400"
                  }`}>{eng.status.toUpperCase().replace("-", " ")}</span>
                </div>
                <div className="flex items-center justify-between mt-2">
                  <span className="text-[10px] text-muted-foreground">{eng.phase}</span>
                  <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                    <Calendar className="w-3 h-3" /> Due: {eng.due}
                  </span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
              <Users className="w-4 h-4 text-blue-400" /> TEAM WORKLOAD
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {[
              { name: "John Doe", initials: "JD", engagements: 2, findings: 34, utilization: 85 },
              { name: "Sarah Kim", initials: "SK", engagements: 1, findings: 28, utilization: 70 },
              { name: "Mike Ross", initials: "MR", engagements: 2, findings: 19, utilization: 90 },
              { name: "Alex Lee", initials: "AL", engagements: 1, findings: 45, utilization: 60 },
              { name: "Tom Kelly", initials: "TK", engagements: 1, findings: 12, utilization: 40 },
              { name: "Nina Patel", initials: "NP", engagements: 1, findings: 22, utilization: 55 },
            ].map((member) => (
              <div key={member.name} className="flex items-center gap-3">
                <div className="w-9 h-9 rounded bg-primary/20 flex items-center justify-center text-xs font-display text-primary shrink-0">
                  {member.initials}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-display tracking-wider">{member.name}</span>
                    <span className="text-[10px] text-muted-foreground">{member.engagements} eng · {member.findings} findings</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 bg-secondary rounded-full h-1.5">
                      <div className={`h-full rounded-full transition-all ${
                        member.utilization > 80 ? "bg-red-500" : member.utilization > 60 ? "bg-amber-500" : "bg-emerald-500"
                      }`} style={{ width: `${member.utilization}%` }} />
                    </div>
                    <span className="text-[10px] font-display tracking-wider w-8 text-right">{member.utilization}%</span>
                  </div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Upcoming Deadlines */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
            <Clock className="w-4 h-4 text-amber-400" /> UPCOMING DEADLINES
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {[
              { date: "Mar 5", task: "External Pentest Report — HealthCo", type: "report", overdue: true },
              { date: "Mar 8", task: "Cloud Pentest Phase 1 Complete — FinServ LLC", type: "milestone", overdue: false },
              { date: "Mar 12", task: "Weekly Status Update — All Engagements", type: "meeting", overdue: false },
              { date: "Mar 15", task: "Project Nightfall Interim Report — Acme Corp", type: "report", overdue: false },
              { date: "Mar 22", task: "Red Team Q1 Final Delivery — TechStart Inc", type: "delivery", overdue: false },
            ].map((deadline, i) => (
              <div key={i} className={`flex items-center gap-3 p-2 rounded ${deadline.overdue ? "bg-red-500/10 border border-red-500/20" : "hover:bg-secondary/30"} transition-colors`}>
                <span className={`text-xs font-display tracking-wider w-14 shrink-0 ${deadline.overdue ? "text-red-400" : "text-muted-foreground"}`}>{deadline.date}</span>
                <div className={`w-2 h-2 rounded-full shrink-0 ${
                  deadline.type === "report" ? "bg-purple-500" : deadline.type === "milestone" ? "bg-blue-500" :
                  deadline.type === "meeting" ? "bg-amber-500" : "bg-emerald-500"
                }`} />
                <span className="text-xs flex-1">{deadline.task}</span>
                {deadline.overdue && <span className="text-[9px] font-display tracking-widest text-red-400">OVERDUE</span>}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
