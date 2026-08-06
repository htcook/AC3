import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Building2, DollarSign, Shield,
  CheckCircle2, Clock, FileText
} from "lucide-react";

function PricingTiersPanel() {
  const { data: tiers } = trpc.msspAnalytics.listPricingTiers.useQuery();

  return (
    <div className="grid grid-cols-4 gap-4">
      {tiers?.map((t: any) => (
        <Card key={t.id} className={`border-border/50 ${t.recommended ? "border-primary/40 bg-primary/5" : ""}`}>
          <CardHeader className="pb-2">
            {t.recommended && <Badge className="w-fit mb-2 text-[10px]">Recommended</Badge>}
            <CardTitle className="text-base">{t.name}</CardTitle>
            <CardDescription className="text-xs">{t.description}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-2xl font-bold">${t.monthlyBase?.toLocaleString()}<span className="text-xs text-muted-foreground font-normal">/mo</span></p>
            <div className="space-y-1">
              {t.features?.map((f: string, i: number) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <CheckCircle2 className="h-3 w-3 text-green-400 shrink-0" />
                  <span>{f}</span>
                </div>
              ))}
            </div>
            <div className="text-xs text-muted-foreground space-y-1 pt-2 border-t border-border/30">
              <p>Scans: {t.includedScans ?? "Unlimited"}</p>
              <p>LLM Calls: {t.includedLlmCalls ?? "Unlimited"}</p>
              <p>Agents: {t.includedAgents ?? "Unlimited"}</p>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function RiskCalculatorPanel() {
  const [factors, setFactors] = useState({
    criticalVulns: 3,
    highVulns: 12,
    mediumVulns: 25,
    lowVulns: 40,
    daysSinceLastAssessment: 45,
    owaspCoveragePercent: 65,
    agentCoverage: 0.7,
    complianceGaps: 4,
    exposedServices: 8,
    unpatched: 15,
  });

  const { data: risk } = trpc.msspAnalytics.calculateRisk.useQuery(factors);

  const riskColor = risk?.level === "critical" ? "text-red-400" : risk?.level === "high" ? "text-orange-400" : risk?.level === "medium" ? "text-yellow-400" : "text-green-400";
  const riskBg = risk?.level === "critical" ? "bg-red-500/10 border-red-500/20" : risk?.level === "high" ? "bg-orange-500/10 border-orange-500/20" : risk?.level === "medium" ? "bg-yellow-500/10 border-yellow-500/20" : "bg-green-500/10 border-green-500/20";

  return (
    <div className="grid grid-cols-3 gap-4">
      <Card className="col-span-2 border-border/50">
        <CardHeader>
          <CardTitle className="text-base">Risk Factor Inputs</CardTitle>
          <CardDescription>Adjust parameters to calculate tenant risk score</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3">
            {Object.entries(factors).map(([key, val]) => (
              <div key={key} className="flex items-center justify-between p-2 rounded-md bg-muted/20">
                <span className="text-xs capitalize">{key.replace(/([A-Z])/g, " $1").trim()}</span>
                <input type="number" value={val ?? 0} onChange={e => setFactors(f => ({ ...f, [key]: parseFloat(e.target.value) || 0 }))} className="w-20 text-right text-xs bg-transparent border-b border-border/50 outline-none font-mono" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
      <Card className={`border-2 ${riskBg}`}>
        <CardContent className="pt-6 flex flex-col items-center justify-center h-full gap-3">
          <Shield className={`h-12 w-12 ${riskColor}`} />
          <p className={`text-4xl font-bold ${riskColor}`}>{risk?.score?.toFixed(0) ?? 0}</p>
          <Badge variant="outline" className={`uppercase text-sm ${riskColor}`}>{risk?.level ?? "unknown"}</Badge>
          <p className="text-xs text-muted-foreground text-center">Composite risk score based on vulnerabilities, coverage, compliance, and exposure</p>
        </CardContent>
      </Card>
    </div>
  );
}

function SlaCompliancePanel() {
  const { data: slaDefinitions } = trpc.msspAnalytics.listSLADefinitions.useQuery();

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><Clock className="h-4 w-4 text-blue-400" /> SLA Definitions</CardTitle>
        <CardDescription>Service level agreements for managed security services</CardDescription>
      </CardHeader>
      <CardContent>
        {slaDefinitions && slaDefinitions.length > 0 ? (
          <div className="space-y-3">
            {slaDefinitions.map((s: any, i: number) => (
              <div key={i} className="flex items-center justify-between p-3 rounded-md bg-muted/20 border border-border/30">
                <div>
                  <p className="text-sm font-medium">{s.name}</p>
                  <p className="text-xs text-muted-foreground">{s.description}</p>
                </div>
                <Badge variant="outline" className="font-mono text-xs">{s.defaultTarget ?? "N/A"}</Badge>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">Loading SLA definitions...</p>
        )}
      </CardContent>
    </Card>
  );
}

/* ─── Main Page ─── */
export default function MsspAnalyticsDashboard() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">MSSP Analytics</h1>
        <p className="text-muted-foreground mt-1">
          Cross-tenant security analytics, billing management, risk scoring, and SLA compliance for managed security service providers.
        </p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-primary/20 p-2"><Building2 className="h-5 w-5 text-primary" /></div>
            <div>
              <p className="text-2xl font-bold">Multi</p>
              <p className="text-xs text-muted-foreground">Tenant Support</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-green-500/20 bg-green-500/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-green-500/20 p-2"><DollarSign className="h-5 w-5 text-green-400" /></div>
            <div>
              <p className="text-2xl font-bold">Usage</p>
              <p className="text-xs text-muted-foreground">Based Billing</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-orange-500/20 bg-orange-500/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-orange-500/20 p-2"><Shield className="h-5 w-5 text-orange-400" /></div>
            <div>
              <p className="text-2xl font-bold">Risk</p>
              <p className="text-xs text-muted-foreground">Scoring Engine</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-blue-500/20 bg-blue-500/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-blue-500/20 p-2"><FileText className="h-5 w-5 text-blue-400" /></div>
            <div>
              <p className="text-2xl font-bold">SLA</p>
              <p className="text-xs text-muted-foreground">Compliance</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="pricing" className="space-y-4">
        <TabsList>
          <TabsTrigger value="pricing">Pricing Tiers</TabsTrigger>
          <TabsTrigger value="risk">Risk Calculator</TabsTrigger>
          <TabsTrigger value="sla">SLA Compliance</TabsTrigger>
        </TabsList>
        <TabsContent value="pricing"><PricingTiersPanel /></TabsContent>
        <TabsContent value="risk"><RiskCalculatorPanel /></TabsContent>
        <TabsContent value="sla"><SlaCompliancePanel /></TabsContent>
      </Tabs>
    </div>
  );
}
