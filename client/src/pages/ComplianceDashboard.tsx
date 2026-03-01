import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Shield, ShieldCheck, ShieldAlert, ShieldX, AlertTriangle,
  CheckCircle2, XCircle, MinusCircle, HelpCircle, TrendingUp,
  FileText, ChevronRight, RefreshCw, Download,
} from "lucide-react";
import { toast } from "sonner";

const statusConfig = {
  compliant: { icon: CheckCircle2, color: "text-emerald-400", bg: "bg-emerald-500/10", badge: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  partial: { icon: MinusCircle, color: "text-amber-400", bg: "bg-amber-500/10", badge: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
  non_compliant: { icon: XCircle, color: "text-red-400", bg: "bg-red-500/10", badge: "bg-red-500/20 text-red-400 border-red-500/30" },
  not_assessed: { icon: HelpCircle, color: "text-zinc-400", bg: "bg-zinc-500/10", badge: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30" },
};

const domainIcons: Record<string, typeof Shield> = {
  fips: ShieldCheck,
  oscal: FileText,
  ksi: TrendingUp,
  retention: Shield,
  auth: ShieldAlert,
  tenant: Shield,
  ai: Shield,
};

function ScoreRing({ score, size = 120 }: { score: number; size?: number }) {
  const radius = (size - 12) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 80 ? "#10b981" : score >= 60 ? "#f59e0b" : "#ef4444";

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={8} />
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth={8}
          strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
          className="transition-all duration-1000 ease-out" />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-white">{score}</span>
        <span className="text-xs text-zinc-400">/ 100</span>
      </div>
    </div>
  );
}

function DomainCard({ domain }: { domain: any }) {
  const [expanded, setExpanded] = useState(false);
  const Icon = domainIcons[domain.domain] || Shield;

  return (
    <Card className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors">
      <CardHeader className="pb-3 cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${domain.overallScore >= 80 ? "bg-emerald-500/10" : domain.overallScore >= 60 ? "bg-amber-500/10" : "bg-red-500/10"}`}>
              <Icon className={`h-5 w-5 ${domain.overallScore >= 80 ? "text-emerald-400" : domain.overallScore >= 60 ? "text-amber-400" : "text-red-400"}`} />
            </div>
            <div>
              <CardTitle className="text-sm font-medium text-zinc-200">{domain.label}</CardTitle>
              <CardDescription className="text-xs">
                {domain.compliantCount}/{domain.totalCount} controls compliant
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className={`text-xl font-bold ${domain.overallScore >= 80 ? "text-emerald-400" : domain.overallScore >= 60 ? "text-amber-400" : "text-red-400"}`}>
              {domain.overallScore}%
            </span>
            <ChevronRight className={`h-4 w-4 text-zinc-500 transition-transform ${expanded ? "rotate-90" : ""}`} />
          </div>
        </div>
        <Progress value={domain.overallScore} className="h-1.5 mt-3 bg-zinc-800" />
      </CardHeader>
      {expanded && (
        <CardContent className="pt-0 space-y-2">
          {domain.controls.map((control: any) => {
            const cfg = statusConfig[control.status as keyof typeof statusConfig];
            const StatusIcon = cfg.icon;
            return (
              <div key={control.id} className="flex items-center justify-between p-2 rounded-lg bg-zinc-800/50">
                <div className="flex items-center gap-2">
                  <StatusIcon className={`h-4 w-4 ${cfg.color}`} />
                  <div>
                    <p className="text-xs font-medium text-zinc-300">{control.name}</p>
                    <p className="text-xs text-zinc-500">{control.details}</p>
                  </div>
                </div>
                <Badge variant="outline" className={cfg.badge}>
                  {control.status.replace("_", " ")}
                </Badge>
              </div>
            );
          })}
        </CardContent>
      )}
    </Card>
  );
}

export default function ComplianceDashboard() {
  const [selectedFramework, setSelectedFramework] = useState<string>("fedramp_high");
  const posture = trpc.complianceDashboard.getPosture.useQuery();
  const gaps = trpc.complianceDashboard.getGaps.useQuery();
  const trend = trpc.complianceDashboard.getTrend.useQuery({ days: 30 });
  const frameworkReport = trpc.complianceDashboard.getFrameworkReport.useQuery(
    { framework: selectedFramework as any },
  );

  if (posture.isLoading) {
    return (
      <div className="p-6 space-y-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-32" />)}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-48" />)}
        </div>
      </div>
    );
  }

  const data = posture.data;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="h-7 w-7 text-emerald-400" />
            Compliance Posture
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Unified view of FIPS, OSCAL, KSI, authentication, and data governance compliance
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => { posture.refetch(); gaps.refetch(); trend.refetch(); toast.success("Refreshing compliance data..."); }}>
            <RefreshCw className="h-4 w-4 mr-1" /> Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={() => toast.info("Export feature coming soon")}>
            <Download className="h-4 w-4 mr-1" /> Export
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      {data && (
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <Card className="bg-zinc-900/50 border-zinc-800 md:col-span-1">
            <CardContent className="pt-6 flex flex-col items-center">
              <ScoreRing score={data.overallScore} />
              <p className="text-xs text-zinc-400 mt-2">Overall Score</p>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="pt-6 text-center">
              <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-white">{data.totalCompliant}</p>
              <p className="text-xs text-zinc-400">Compliant</p>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="pt-6 text-center">
              <MinusCircle className="h-8 w-8 text-amber-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-white">{data.totalPartial}</p>
              <p className="text-xs text-zinc-400">Partial</p>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="pt-6 text-center">
              <XCircle className="h-8 w-8 text-red-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-white">{data.totalNonCompliant}</p>
              <p className="text-xs text-zinc-400">Non-Compliant</p>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="pt-6 text-center">
              <HelpCircle className="h-8 w-8 text-zinc-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-white">{data.totalNotAssessed}</p>
              <p className="text-xs text-zinc-400">Not Assessed</p>
            </CardContent>
          </Card>
        </div>
      )}

      <Tabs defaultValue="domains" className="space-y-4">
        <TabsList className="bg-zinc-900 border border-zinc-800">
          <TabsTrigger value="domains">Compliance Domains</TabsTrigger>
          <TabsTrigger value="gaps">Gaps & Remediation</TabsTrigger>
          <TabsTrigger value="frameworks">Framework Reports</TabsTrigger>
        </TabsList>

        {/* Domains Tab */}
        <TabsContent value="domains" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {data?.domains.map((domain: any) => (
              <DomainCard key={domain.domain} domain={domain} />
            ))}
          </div>
        </TabsContent>

        {/* Gaps Tab */}
        <TabsContent value="gaps" className="space-y-4">
          {gaps.data?.gaps.length === 0 ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="pt-6 text-center">
                <ShieldCheck className="h-12 w-12 text-emerald-400 mx-auto mb-3" />
                <p className="text-lg font-medium text-white">All Controls Compliant</p>
                <p className="text-sm text-zinc-400">No compliance gaps detected</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {gaps.data?.gaps.map((gap: any) => {
                const cfg = statusConfig[gap.status as keyof typeof statusConfig];
                const StatusIcon = cfg.icon;
                const priorityColors: Record<string, string> = {
                  critical: "bg-red-500/20 text-red-400 border-red-500/30",
                  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
                  medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
                  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
                };
                return (
                  <Card key={gap.id} className="bg-zinc-900/50 border-zinc-800">
                    <CardContent className="pt-4">
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-3">
                          <StatusIcon className={`h-5 w-5 mt-0.5 ${cfg.color}`} />
                          <div>
                            <div className="flex items-center gap-2">
                              <p className="text-sm font-medium text-zinc-200">{gap.name}</p>
                              <Badge variant="outline" className={priorityColors[gap.priority] || ""}>
                                {gap.priority}
                              </Badge>
                              <Badge variant="outline" className="bg-zinc-800 text-zinc-400 border-zinc-700">
                                {gap.framework}
                              </Badge>
                            </div>
                            <p className="text-xs text-zinc-500 mt-1">{gap.details}</p>
                            <div className="mt-2 p-2 rounded bg-zinc-800/50 border border-zinc-700/50">
                              <p className="text-xs text-zinc-300">
                                <AlertTriangle className="h-3 w-3 inline mr-1 text-amber-400" />
                                <strong>Recommendation:</strong> {gap.recommendation}
                              </p>
                            </div>
                          </div>
                        </div>
                        <span className={`text-lg font-bold ${gap.score < 30 ? "text-red-400" : gap.score < 60 ? "text-amber-400" : "text-zinc-400"}`}>
                          {gap.score}%
                        </span>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* Frameworks Tab */}
        <TabsContent value="frameworks" className="space-y-4">
          <div className="flex items-center gap-3 mb-4">
            <Select value={selectedFramework} onValueChange={setSelectedFramework}>
              <SelectTrigger className="w-64 bg-zinc-900 border-zinc-700">
                <SelectValue placeholder="Select framework" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="fedramp_high">FedRAMP High</SelectItem>
                <SelectItem value="fedramp_moderate">FedRAMP Moderate</SelectItem>
                <SelectItem value="nist_800_53">NIST SP 800-53 Rev 5</SelectItem>
                <SelectItem value="nist_800_171">NIST SP 800-171 Rev 2</SelectItem>
                <SelectItem value="cmmc_level2">CMMC Level 2</SelectItem>
                <SelectItem value="cmmc_level3">CMMC Level 3</SelectItem>
                <SelectItem value="hipaa">HIPAA Security Rule</SelectItem>
                <SelectItem value="pci_dss">PCI DSS v4.0</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {frameworkReport.isLoading ? (
            <Skeleton className="h-64" />
          ) : frameworkReport.data && (
            <div className="space-y-4">
              <Card className="bg-zinc-900/50 border-zinc-800">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-lg text-white">{frameworkReport.data.framework}</CardTitle>
                      <CardDescription>
                        {frameworkReport.data.implementedControls} of {frameworkReport.data.totalControls} controls implemented
                      </CardDescription>
                    </div>
                    <div className="text-right">
                      <span className={`text-3xl font-bold ${frameworkReport.data.overallScore >= 80 ? "text-emerald-400" : frameworkReport.data.overallScore >= 60 ? "text-amber-400" : "text-red-400"}`}>
                        {frameworkReport.data.overallScore}%
                      </span>
                    </div>
                  </div>
                  <Progress value={frameworkReport.data.overallScore} className="h-2 mt-3 bg-zinc-800" />
                </CardHeader>
              </Card>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {frameworkReport.data.families.map((family: any) => (
                  <Card key={family.family} className="bg-zinc-900/50 border-zinc-800">
                    <CardContent className="pt-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-medium text-zinc-300">{family.family}</span>
                        <span className={`text-sm font-bold ${family.score >= 80 ? "text-emerald-400" : family.score >= 60 ? "text-amber-400" : "text-red-400"}`}>
                          {family.score}%
                        </span>
                      </div>
                      <Progress value={family.score} className="h-1.5 bg-zinc-800" />
                      <p className="text-xs text-zinc-500 mt-1">{family.implemented}/{family.total} controls</p>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Footer */}
      {data && (
        <p className="text-xs text-zinc-500 text-center">
          Last assessed: {new Date(data.lastUpdated).toLocaleString()} by {data.assessedBy}
        </p>
      )}
    </div>
  );
}
