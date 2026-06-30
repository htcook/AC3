import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import {
  Cloud, Shield, AlertTriangle, CheckCircle2, XCircle,
  Server, Container, Zap, Lock, BarChart3, Play, Loader2
} from "lucide-react";

type CloudProvider = "aws" | "azure" | "gcp";

const PROVIDER_INFO: Record<CloudProvider, { name: string; color: string; icon: string }> = {
  aws: { name: "Amazon Web Services", color: "text-orange-400", icon: "🟠" },
  azure: { name: "Microsoft Azure", color: "text-blue-400", icon: "🔵" },
  gcp: { name: "Google Cloud Platform", color: "text-green-400", icon: "🟢" },
};

/* ─── Assessment Runner ─── */
function AssessmentRunner() {
  const [provider, setProvider] = useState<CloudProvider>("aws");
  
  const { data: categories } = trpc.cloudWorkloadTesting.getCategories.useQuery({ provider });
  const runMutation = trpc.cloudWorkloadTesting.runAssessment.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.summary?.totalChecks ?? 0} checks completed — Grade: ${data.grade}`);
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Select value={provider} onValueChange={v => setProvider(v as CloudProvider)}>
          <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="aws">AWS</SelectItem>
            <SelectItem value="azure">Azure</SelectItem>
            <SelectItem value="gcp">GCP</SelectItem>
          </SelectContent>
        </Select>
        <Button onClick={() => runMutation.mutate({ provider, dryRun: true })} disabled={runMutation.isPending}>
          {runMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Play className="h-4 w-4 mr-2" />}
          Run Assessment
        </Button>
      </div>

      {categories && (
        <div className="grid grid-cols-2 gap-3">
          {categories.map((cat: any) => (
            <Card key={cat.category} className="border-border/50">
              <CardContent className="pt-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium capitalize">{cat.category.replace(/_/g, " ")}</span>
                  <Badge variant="outline" className="text-[10px]">{cat.checkCount} checks</Badge>
                </div>
                <p className="text-xs text-muted-foreground">{cat.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {runMutation.data && (
        <Card className="border-primary/20">
          <CardHeader>
            <CardTitle className="text-base">Assessment Results — {PROVIDER_INFO[provider].name}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-4 gap-3">
              <div className="rounded-md bg-green-500/10 border border-green-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-green-400">{runMutation.data.summary?.passed ?? 0}</p>
                <p className="text-xs text-muted-foreground">Passed</p>
              </div>
              <div className="rounded-md bg-red-500/10 border border-red-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-red-400">{runMutation.data.summary?.failed ?? 0}</p>
                <p className="text-xs text-muted-foreground">Failed</p>
              </div>
              <div className="rounded-md bg-yellow-500/10 border border-yellow-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-yellow-400">{runMutation.data.summary?.warnings ?? 0}</p>
                <p className="text-xs text-muted-foreground">Warnings</p>
              </div>
              <div className="rounded-md bg-blue-500/10 border border-blue-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-blue-400">{runMutation.data.summary?.complianceScore?.toFixed(0) ?? 0}%</p>
                <p className="text-xs text-muted-foreground">Score</p>
              </div>
            </div>
            {runMutation.data.results && runMutation.data.results.length > 0 && (
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {runMutation.data.results.slice(0, 20).map((r: any, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-xs p-2 rounded-md bg-muted/20">
                    {r.status === "pass" ? <CheckCircle2 className="h-3.5 w-3.5 text-green-400 shrink-0" /> :
                     r.status === "fail" ? <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" /> :
                     <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 shrink-0" />}
                    <span className="text-foreground">{r.checkName}</span>
                    <Badge variant="outline" className="ml-auto text-[10px] capitalize">{r.category}</Badge>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/* ─── K8s & Serverless Checks ─── */
function ContainerSecurityPanel() {
  const { data: k8sChecks } = trpc.cloudWorkloadTesting.getK8sChecks.useQuery();
  const { data: serverlessChecks } = trpc.cloudWorkloadTesting.getServerlessChecks.useQuery();

  return (
    <div className="space-y-4">
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Container className="h-4 w-4 text-cyan-400" /> Kubernetes Security Checks</CardTitle>
          <CardDescription>CIS Kubernetes Benchmark and container runtime security validation</CardDescription>
        </CardHeader>
        <CardContent>
          {k8sChecks && k8sChecks.length > 0 ? (
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {k8sChecks.map((c: any, i: number) => (
                <div key={i} className="flex items-center gap-2 text-xs p-2 rounded-md bg-muted/20 border border-border/30">
                  <Shield className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                  <span className="text-foreground font-medium">{c.name}</span>
                  <Badge variant={c.severity === "critical" ? "destructive" : c.severity === "high" ? "destructive" : "secondary"} className="ml-auto text-[10px]">{c.severity}</Badge>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">Loading K8s security checks...</p>
          )}
        </CardContent>
      </Card>

      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Zap className="h-4 w-4 text-yellow-400" /> Serverless Security Checks</CardTitle>
          <CardDescription>Lambda/Cloud Functions security validation and misconfiguration detection</CardDescription>
        </CardHeader>
        <CardContent>
          {serverlessChecks && serverlessChecks.length > 0 ? (
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {serverlessChecks.map((c: any, i: number) => (
                <div key={i} className="flex items-center gap-2 text-xs p-2 rounded-md bg-muted/20 border border-border/30">
                  <Lock className="h-3.5 w-3.5 text-yellow-400 shrink-0" />
                  <span className="text-foreground font-medium">{c.name}</span>
                  <Badge variant={c.severity === "critical" ? "destructive" : c.severity === "high" ? "destructive" : "secondary"} className="ml-auto text-[10px]">{c.severity}</Badge>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">Loading serverless security checks...</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

/* ─── Multi-Cloud Comparison ─── */
function MultiCloudComparison() {
  
  const compareMutation = trpc.cloudWorkloadTesting.compareProviders.useMutation({
    onSuccess: () => toast.success("Comparison Complete"),
  });

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><BarChart3 className="h-4 w-4 text-purple-400" /> Multi-Cloud Comparison</CardTitle>
        <CardDescription>Compare security posture across AWS, Azure, and GCP side by side</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Button onClick={() => compareMutation.mutate({ providers: ["aws", "azure", "gcp"] })} disabled={compareMutation.isPending} className="w-full">
          {compareMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <BarChart3 className="h-4 w-4 mr-2" />}
          Compare All Providers
        </Button>
        {compareMutation.data && (
          <div className="space-y-3">
            {compareMutation.data.providers?.map((p: any) => (
              <div key={p.provider} className="rounded-md border border-border/50 p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">{PROVIDER_INFO[p.provider as CloudProvider]?.name ?? p.provider}</span>
                  <Badge variant={p.complianceScore >= 80 ? "default" : p.complianceScore >= 60 ? "secondary" : "destructive"} className="text-xs">{p.complianceScore?.toFixed(0)}%</Badge>
                </div>
                <Progress value={p.complianceScore ?? 0} className="h-2" />
                <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
                  <span className="text-green-400">{p.passed} passed</span>
                  <span className="text-red-400">{p.failed} failed</span>
                  <span className="text-yellow-400">{p.criticalFindings} critical</span>
                </div>
              </div>
            ))}
            {compareMutation.data.commonGaps?.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium text-muted-foreground">Common Security Gaps:</p>
                {compareMutation.data.commonGaps.map((r: string, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs p-2 rounded-md bg-muted/20">
                    <AlertTriangle className="h-3.5 w-3.5 text-orange-400 shrink-0 mt-0.5" />
                    <span>{r}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/* ─── Main Page ─── */
export default function CloudWorkloadTesting() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Cloud Workload Testing</h1>
        <p className="text-muted-foreground mt-1">
          Unified cloud security assessment across AWS, Azure, and GCP — including CIS benchmarks, IAM audits, container/K8s, and serverless security.
        </p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {(["aws", "azure", "gcp"] as const).map(p => (
          <Card key={p} className="border-border/50">
            <CardContent className="pt-4 flex items-center gap-3">
              <div className="text-2xl">{PROVIDER_INFO[p].icon}</div>
              <div>
                <p className={`text-sm font-bold ${PROVIDER_INFO[p].color}`}>{PROVIDER_INFO[p].name}</p>
                <p className="text-xs text-muted-foreground">CIS + IAM + Storage + Attack Paths</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs defaultValue="assess" className="space-y-4">
        <TabsList>
          <TabsTrigger value="assess">Run Assessment</TabsTrigger>
          <TabsTrigger value="containers">K8s & Serverless</TabsTrigger>
          <TabsTrigger value="compare">Multi-Cloud Compare</TabsTrigger>
        </TabsList>
        <TabsContent value="assess"><AssessmentRunner /></TabsContent>
        <TabsContent value="containers"><ContainerSecurityPanel /></TabsContent>
        <TabsContent value="compare"><MultiCloudComparison /></TabsContent>
      </Tabs>
    </div>
  );
}
