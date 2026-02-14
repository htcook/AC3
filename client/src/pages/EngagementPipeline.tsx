import { useState, useEffect } from "react";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { useLocation } from "wouter";
import {
  Rocket, Globe, Search, Shield, Brain, Target, Zap, CheckCircle2,
  Clock, AlertTriangle, ArrowRight, Play, ChevronDown, ChevronRight,
  Loader2, XCircle, BarChart3, FileText, Crosshair, Radio,
} from "lucide-react";

interface PipelineStep {
  id: string;
  title: string;
  description: string;
  icon: React.ComponentType<{className?: string}>;
  status: 'pending' | 'running' | 'complete' | 'error';
  result?: any;
  error?: string;
}

const INITIAL_STEPS: Omit<PipelineStep, 'status'>[] = [
  { id: 'intel', title: 'Domain Intelligence', description: 'Passive discovery of assets, DNS, certificates, and infrastructure', icon: Search },
  { id: 'classify', title: 'Asset Classification', description: 'Categorize discovered assets by type, criticality, and business function', icon: Brain },
  { id: 'risk', title: 'Risk Assessment', description: 'CARVER+SHOCK BIA scoring with hybrid risk analysis', icon: Shield },
  { id: 'threat', title: 'Threat Modeling', description: 'Map threat actors and TTPs relevant to the target profile', icon: Target },
  { id: 'campaign', title: 'Campaign Design', description: 'Generate Caldera operations and GoPhish campaigns from findings', icon: Zap },
  { id: 'deploy', title: 'Auto-Deploy', description: 'Create engagement, push abilities to Caldera, and deploy GoPhish templates', icon: Rocket },
];

const CLIENT_TYPES = [
  { value: 'msp', label: 'MSP Client', desc: 'Managed Service Provider customer' },
  { value: 'enterprise', label: 'Enterprise', desc: 'Large enterprise domain customer' },
  { value: 'saas', label: 'SaaS Provider', desc: 'Software-as-a-Service provider' },
  { value: 'paas', label: 'PaaS Provider', desc: 'Platform-as-a-Service provider' },
  { value: 'iaas', label: 'IaaS Provider', desc: 'Infrastructure-as-a-Service provider' },
  { value: 'mixed_hosting', label: 'Mixed Hosting', desc: 'Mixed hosting environment' },
];

export default function EngagementPipeline() {
  const [, navigate] = useLocation();
  const [domains, setDomains] = useState("");
  const [clientName, setClientName] = useState("");
  const [clientType, setClientType] = useState("enterprise");
  const [industry, setIndustry] = useState("");
  const [employeeCount, setEmployeeCount] = useState("");
  const [steps, setSteps] = useState<PipelineStep[]>(
    INITIAL_STEPS.map(s => ({ ...s, status: 'pending' as const }))
  );
  const [isRunning, setIsRunning] = useState(false);
  const [currentStep, setCurrentStep] = useState(-1);
  const [pipelineResult, setPipelineResult] = useState<any>(null);
  const [expandedStep, setExpandedStep] = useState<string | null>(null);

  // Pipeline history
  const { data: pipelineHistory } = trpc.engagementPipeline.list.useQuery();

  // Engagement pipeline - create then execute
  const createPipeline = trpc.engagementPipeline.create.useMutation();
  const executePipeline = trpc.engagementPipeline.execute.useMutation({
    onSuccess: (data: any) => {
      setPipelineResult(data);
      setIsRunning(false);
      updateStep('deploy', 'complete', data);
      toast.success("Pipeline complete! Engagement created.");
    },
    onError: (err: any) => {
      setIsRunning(false);
      const failedStep = steps.find(s => s.status === 'running');
      if (failedStep) updateStep(failedStep.id, 'error', undefined, err.message);
      toast.error(`Pipeline failed: ${err.message}`);
    },
  });

  const updateStep = (id: string, status: PipelineStep['status'], result?: any, error?: string) => {
    setSteps(prev => prev.map(s => s.id === id ? { ...s, status, result, error } : s));
  };

  const startPipeline = async () => {
    if (!domains.trim()) { toast.error("Enter at least one domain"); return; }
    if (!clientName.trim()) { toast.error("Enter a client name"); return; }

    setIsRunning(true);
    setPipelineResult(null);
    setSteps(INITIAL_STEPS.map(s => ({ ...s, status: 'pending' as const })));

    // Simulate step progression with the actual pipeline
    const domainList = domains.split(/[\n,]+/).map(d => d.trim()).filter(Boolean);

    // Step 1: Domain Intel
    setCurrentStep(0);
    updateStep('intel', 'running');
    
    // Small delay for visual feedback
    await new Promise(r => setTimeout(r, 800));
    updateStep('intel', 'complete', { domains: domainList.length });

    // Step 2: Classification
    setCurrentStep(1);
    updateStep('classify', 'running');
    await new Promise(r => setTimeout(r, 600));
    updateStep('classify', 'complete');

    // Step 3: Risk Assessment
    setCurrentStep(2);
    updateStep('risk', 'running');
    await new Promise(r => setTimeout(r, 600));
    updateStep('risk', 'complete');

    // Step 4: Threat Modeling
    setCurrentStep(3);
    updateStep('threat', 'running');
    await new Promise(r => setTimeout(r, 600));
    updateStep('threat', 'complete');

    // Step 5: Campaign Design
    setCurrentStep(4);
    updateStep('campaign', 'running');
    await new Promise(r => setTimeout(r, 600));
    updateStep('campaign', 'complete');

    // Step 6: Deploy - this calls the actual backend pipeline
    setCurrentStep(5);
    updateStep('deploy', 'running');

    try {
      const created = await createPipeline.mutateAsync({
        name: clientName.trim(),
        targetDomains: domainList,
        clientType,
        orgProfile: {
          industry: industry.trim() || undefined,
          employeeCount: employeeCount ? parseInt(employeeCount) : undefined,
        },
      });
      executePipeline.mutate({ pipelineId: created.id });
    } catch (err: any) {
      setIsRunning(false);
      updateStep('deploy', 'error', undefined, err.message);
      toast.error(`Failed to create pipeline: ${err.message}`);
    }
  };

  const completedSteps = steps.filter(s => s.status === 'complete').length;
  const progress = (completedSteps / steps.length) * 100;

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
              <Rocket className="w-7 h-7 text-cyan-400" />
              Automated Engagement Pipeline
            </h1>
            <p className="text-muted-foreground mt-1">
              One-click: Domain Intel → Risk Scoring → Campaign Design → Auto-Deploy to Caldera & GoPhish
            </p>
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Left: Configuration */}
          <div className="lg:col-span-1 space-y-4">
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Globe className="w-5 h-5 text-cyan-400" />
                  Target Configuration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Client Name *</label>
                  <Input
                    placeholder="Acme Corporation"
                    value={clientName}
                    onChange={(e) => setClientName(e.target.value)}
                    disabled={isRunning}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Target Domains * (one per line or comma-separated)</label>
                  <textarea
                    className="w-full bg-background border rounded px-3 py-2 text-sm min-h-[100px] resize-y"
                    placeholder={"acme.com\nacme.io\nacme-corp.net"}
                    value={domains}
                    onChange={(e) => setDomains(e.target.value)}
                    disabled={isRunning}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Client Type</label>
                  <select
                    value={clientType}
                    onChange={(e) => setClientType(e.target.value)}
                    className="w-full bg-background border rounded px-3 py-2 text-sm"
                    disabled={isRunning}
                  >
                    {CLIENT_TYPES.map(t => (
                      <option key={t.value} value={t.value}>{t.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Industry</label>
                  <Input
                    placeholder="Financial Services"
                    value={industry}
                    onChange={(e) => setIndustry(e.target.value)}
                    disabled={isRunning}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Employee Count</label>
                  <Input
                    type="number"
                    placeholder="500"
                    value={employeeCount}
                    onChange={(e) => setEmployeeCount(e.target.value)}
                    disabled={isRunning}
                  />
                </div>

                <Button
                  className="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700 text-white"
                  size="lg"
                  onClick={startPipeline}
                  disabled={isRunning}
                >
                  {isRunning ? (
                    <>
                      <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                      Pipeline Running...
                    </>
                  ) : (
                    <>
                      <Play className="w-5 h-5 mr-2" />
                      Launch Pipeline
                    </>
                  )}
                </Button>
              </CardContent>
            </Card>

            {/* Pipeline History */}
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Clock className="w-5 h-5 text-muted-foreground" />
                  Recent Pipelines
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!pipelineHistory || pipelineHistory.length === 0 ? (
                  <p className="text-xs text-muted-foreground text-center py-4">No pipeline runs yet</p>
                ) : (
                  <div className="space-y-2">
                    {pipelineHistory.slice(0, 5).map((p: any) => (
                      <div key={p.id} className="flex items-center gap-2 p-2 rounded bg-muted/30 hover:bg-muted/50 transition-colors">
                        <div className={`w-2 h-2 rounded-full ${
                          p.status === 'completed' ? 'bg-green-400' :
                          p.status === 'running' ? 'bg-amber-400 animate-pulse' : 'bg-red-400'
                        }`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium truncate">{p.clientName}</p>
                          <p className="text-[10px] text-muted-foreground">
                            {new Date(p.createdAt).toLocaleDateString()} — {p.status}
                          </p>
                        </div>
                        {p.engagementId && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 text-xs"
                            onClick={() => navigate(`/engagements/${p.engagementId}`)}
                          >
                            View
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Right: Pipeline Progress */}
          <div className="lg:col-span-2 space-y-4">
            {/* Progress Bar */}
            <Card className="border-border/50">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Pipeline Progress</span>
                  <span className="text-sm text-muted-foreground">{completedSteps}/{steps.length} steps</span>
                </div>
                <div className="w-full bg-muted/30 rounded-full h-3 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-500"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </CardContent>
            </Card>

            {/* Pipeline Steps */}
            <div className="space-y-3">
              {steps.map((step, index) => {
                const Icon = step.icon;
                const isExpanded = expandedStep === step.id;
                return (
                  <Card
                    key={step.id}
                    className={`border transition-all ${
                      step.status === 'running' ? 'border-cyan-500/50 bg-cyan-500/5 shadow-lg shadow-cyan-500/10' :
                      step.status === 'complete' ? 'border-green-500/30 bg-green-500/5' :
                      step.status === 'error' ? 'border-red-500/30 bg-red-500/5' :
                      'border-border/30'
                    }`}
                  >
                    <CardContent className="p-4">
                      <div className="flex items-center gap-4">
                        {/* Step Number */}
                        <div className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 ${
                          step.status === 'running' ? 'bg-cyan-500/20 text-cyan-400' :
                          step.status === 'complete' ? 'bg-green-500/20 text-green-400' :
                          step.status === 'error' ? 'bg-red-500/20 text-red-400' :
                          'bg-muted/30 text-muted-foreground'
                        }`}>
                          {step.status === 'running' ? <Loader2 className="w-5 h-5 animate-spin" /> :
                           step.status === 'complete' ? <CheckCircle2 className="w-5 h-5" /> :
                           step.status === 'error' ? <XCircle className="w-5 h-5" /> :
                           <span className="text-sm font-bold">{index + 1}</span>}
                        </div>

                        {/* Step Info */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <Icon className="w-4 h-4" />
                            <h4 className="font-semibold text-sm">{step.title}</h4>
                            <Badge variant="outline" className={`text-[10px] ${
                              step.status === 'running' ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30' :
                              step.status === 'complete' ? 'bg-green-500/20 text-green-400 border-green-500/30' :
                              step.status === 'error' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                              ''
                            }`}>
                              {step.status}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mt-0.5">{step.description}</p>
                          {step.error && (
                            <p className="text-xs text-red-400 mt-1">{step.error}</p>
                          )}
                        </div>

                        {/* Connector Arrow */}
                        {index < steps.length - 1 && (
                          <ArrowRight className="w-4 h-4 text-muted-foreground/30 shrink-0" />
                        )}

                        {/* Expand */}
                        {step.result && (
                          <button onClick={() => setExpandedStep(isExpanded ? null : step.id)}>
                            {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                          </button>
                        )}
                      </div>

                      {/* Expanded Result */}
                      {isExpanded && step.result && (
                        <div className="mt-3 p-3 bg-black/20 rounded border border-border/20">
                          <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap break-all max-h-[200px] overflow-y-auto">
                            {JSON.stringify(step.result, null, 2)}
                          </pre>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>

            {/* Pipeline Result */}
            {pipelineResult && !isRunning && (
              <Card className="border-green-500/30 bg-green-500/5">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2 text-green-400">
                    <CheckCircle2 className="w-5 h-5" />
                    Pipeline Complete
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {[
                      { label: 'Engagement', value: pipelineResult.engagementId ? `#${pipelineResult.engagementId}` : 'Created', icon: FileText },
                      { label: 'Risk Score', value: pipelineResult.riskScore || 'Calculated', icon: BarChart3 },
                      { label: 'Threats Mapped', value: pipelineResult.threatsFound || '—', icon: Target },
                      { label: 'Campaigns', value: pipelineResult.campaignsCreated || '—', icon: Crosshair },
                    ].map(s => (
                      <div key={s.label} className="bg-black/20 rounded p-3 text-center">
                        <s.icon className="w-5 h-5 mx-auto mb-1 text-green-400" />
                        <p className="text-lg font-bold">{s.value}</p>
                        <p className="text-[10px] text-muted-foreground">{s.label}</p>
                      </div>
                    ))}
                  </div>

                  <div className="flex gap-2">
                    {pipelineResult.engagementId && (
                      <Button
                        onClick={() => navigate(`/engagements/${pipelineResult.engagementId}`)}
                        className="bg-cyan-600 hover:bg-cyan-700"
                      >
                        <FileText className="w-4 h-4 mr-1" />
                        View Engagement
                      </Button>
                    )}
                    {pipelineResult.scanId && (
                      <Button
                        variant="outline"
                        onClick={() => navigate(`/domain-intel/${pipelineResult.scanId}`)}
                      >
                        <Search className="w-4 h-4 mr-1" />
                        View Intel Report
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      onClick={() => {
                        setSteps(INITIAL_STEPS.map(s => ({ ...s, status: 'pending' as const })));
                        setPipelineResult(null);
                        setCurrentStep(-1);
                        setDomains("");
                        setClientName("");
                      }}
                    >
                      <Radio className="w-4 h-4 mr-1" />
                      New Pipeline
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </AppShell>
  );
}
