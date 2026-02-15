import { useState, useMemo, useEffect, useRef } from "react";
import { trpc } from "@/lib/trpc";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import {
  Globe, Search, Shield, Target, ChevronRight, ChevronLeft, Plus, X,
  Loader2, CheckCircle2, AlertTriangle, Zap, Building2, Server, Cloud,
  Network, FileText, Brain, Crosshair
} from "lucide-react";

const CLIENT_TYPES = [
  { value: "msp", label: "MSP / Managed Service Provider", icon: Server, desc: "Multi-tenant management, RMM, PSA platforms" },
  { value: "enterprise", label: "Enterprise Domain", icon: Building2, desc: "Corporate SSO, AD, Exchange, ERP systems" },
  { value: "saas", label: "SaaS Provider", icon: Cloud, desc: "API endpoints, customer dashboards, CI/CD" },
  { value: "paas", label: "PaaS Provider", icon: Network, desc: "Container registries, orchestration, dev portals" },
  { value: "iaas", label: "IaaS Provider", icon: Server, desc: "Cloud consoles, hypervisors, storage APIs" },
  { value: "mixed_hosting", label: "Mixed Hosting", icon: Globe, desc: "Shared hosting, dedicated servers, DNS management" },
  { value: "other", label: "Other", icon: Shield, desc: "Custom environment type" },
];

const SECTORS = [
  "Technology", "Financial Services", "Healthcare", "Government", "Education",
  "Manufacturing", "Retail", "Energy", "Telecommunications", "Legal",
  "Media & Entertainment", "Non-Profit", "Defense", "Transportation", "Other"
];

const CRITICAL_FUNCTIONS = [
  "identity", "email", "payments", "customer_data", "intellectual_property",
  "supply_chain", "communications", "operations", "compliance", "hr",
  "development", "infrastructure", "sales", "marketing", "support"
];

const COMPLIANCE_FLAGS = [
  "SOC2", "HIPAA", "PCI-DSS", "GDPR", "NIST", "ISO27001", "FedRAMP",
  "CMMC", "SOX", "CCPA", "FERPA", "ITAR"
];

type Step = "client_type" | "org_profile" | "domains" | "review" | "running" | "complete";

export default function DomainIntel() {
  const [, navigate] = useLocation();
  const [step, setStep] = useState<Step>("client_type");

  // Pre-fill domain from query parameter (from landing page search)
  const urlParams = new URLSearchParams(window.location.search);
  const domainFromQuery = urlParams.get("domain") || "";

  // Form state
  const [clientType, setClientType] = useState("");
  const [customerName, setCustomerName] = useState("");
  const [sector, setSector] = useState("");
  const [primaryDomain, setPrimaryDomain] = useState(domainFromQuery);
  const [additionalDomains, setAdditionalDomains] = useState<string[]>([]);
  const [newDomain, setNewDomain] = useState("");
  const [criticalFunctions, setCriticalFunctions] = useState<string[]>([]);
  const [complianceFlags, setComplianceFlags] = useState<string[]>([]);
  const [notes, setNotes] = useState("");

  // Pipeline state
  const [scanId, setScanId] = useState<number | null>(null);
  const [pipelineStage, setPipelineStage] = useState(0);
  const [pipelineError, setPipelineError] = useState<string | null>(null);
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const startScan = trpc.domainIntel.startScan.useMutation({
    onSuccess: (data) => {
      setScanId(data.scanId);
      setStep("running");
      setPipelineStage(0);
      setPipelineError(null);
    },
    onError: (err) => {
      setStep("review");
      setPipelineError(err.message);
    },
  });

  // Poll for scan status while running
  const scanStatusQuery = trpc.domainIntel.getScanStatus.useQuery(
    { scanId: scanId! },
    {
      enabled: step === "running" && scanId !== null,
      refetchInterval: 3000, // Poll every 3 seconds
    }
  );

  // React to scan status changes
  useEffect(() => {
    if (!scanStatusQuery.data || step !== "running") return;
    const { status } = scanStatusQuery.data;

    // Update pipeline stage indicator
    const stageMap: Record<string, number> = {
      discovering: 1,
      analyzing: 2,
      scoring: 3,
      recommending: 4,
      completed: 5,
      failed: -1,
    };
    const stageNum = stageMap[status] ?? 0;
    if (stageNum > 0) setPipelineStage(stageNum);

    if (status === "completed") {
      setStep("complete");
    } else if (status === "failed") {
      setPipelineError("Pipeline failed. Please try again.");
      setStep("review");
    }
  }, [scanStatusQuery.data, step]);

  // Past scans
  const scansQuery = trpc.domainIntel.listScans.useQuery();

  const addDomain = () => {
    const d = newDomain.trim().toLowerCase();
    if (d && !additionalDomains.includes(d) && d !== primaryDomain) {
      setAdditionalDomains([...additionalDomains, d]);
      setNewDomain("");
    }
  };

  const removeDomain = (d: string) => {
    setAdditionalDomains(additionalDomains.filter(x => x !== d));
  };

  const toggleFunction = (f: string) => {
    setCriticalFunctions(prev =>
      prev.includes(f) ? prev.filter(x => x !== f) : [...prev, f]
    );
  };

  const toggleCompliance = (f: string) => {
    setComplianceFlags(prev =>
      prev.includes(f) ? prev.filter(x => x !== f) : [...prev, f]
    );
  };

  const handleStartScan = () => {
    setPipelineError(null);
    setPipelineStage(0);
    startScan.mutate({
      primaryDomain,
      additionalDomains,
      clientType: clientType as any,
      sector,
      customerName,
      criticalFunctions,
      complianceFlags,
      notes: notes || undefined,
    });
  };

  const canProceed = useMemo(() => {
    switch (step) {
      case "client_type": return !!clientType;
      case "org_profile": return !!customerName && !!sector;
      case "domains": return !!primaryDomain;
      case "review": return true;
      default: return false;
    }
  }, [step, clientType, customerName, sector, primaryDomain]);

  const nextStep = () => {
    const steps: Step[] = ["client_type", "org_profile", "domains", "review"];
    const idx = steps.indexOf(step);
    if (idx < steps.length - 1) setStep(steps[idx + 1]);
  };

  const prevStep = () => {
    const steps: Step[] = ["client_type", "org_profile", "domains", "review"];
    const idx = steps.indexOf(step);
    if (idx > 0) setStep(steps[idx - 1]);
  };

  const stepIndex = ["client_type", "org_profile", "domains", "review"].indexOf(step);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Brain className="h-7 w-7 text-purple-400" />
            Domain Intelligence Pipeline
          </h1>
          <p className="text-muted-foreground mt-1">
            LLM-powered passive discovery, CARVER+SHOCK risk scoring, and auto-designed campaigns
          </p>
        </div>
        {scansQuery.data && scansQuery.data.length > 0 && step !== "running" && step !== "complete" && (
          <Button variant="outline" onClick={() => navigate("/domain-intel/history")}>
            <FileText className="h-4 w-4 mr-2" />
            View Past Scans ({scansQuery.data.length})
          </Button>
        )}
      </div>

      {/* Progress Steps */}
      {step !== "running" && step !== "complete" && (
        <div className="flex items-center gap-2">
          {["Client Type", "Organization", "Domains", "Review & Launch"].map((label, i) => (
            <div key={label} className="flex items-center gap-2">
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium transition-all ${
                i === stepIndex ? "bg-purple-500/20 text-purple-400 ring-1 ring-purple-500/40" :
                i < stepIndex ? "bg-emerald-500/20 text-emerald-400" :
                "bg-muted text-muted-foreground"
              }`}>
                {i < stepIndex ? <CheckCircle2 className="h-4 w-4" /> : <span className="w-5 h-5 rounded-full bg-current/20 flex items-center justify-center text-xs">{i + 1}</span>}
                <span className="hidden sm:inline">{label}</span>
              </div>
              {i < 3 && <ChevronRight className="h-4 w-4 text-muted-foreground" />}
            </div>
          ))}
        </div>
      )}

      {/* Step 1: Client Type */}
      {step === "client_type" && (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Select Client Type</h2>
          <p className="text-sm text-muted-foreground">
            This determines how the pipeline classifies assets and tailors campaign recommendations.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {CLIENT_TYPES.map(ct => {
              const Icon = ct.icon;
              const selected = clientType === ct.value;
              return (
                <Card
                  key={ct.value}
                  className={`cursor-pointer transition-all hover:border-purple-500/50 ${
                    selected ? "border-purple-500 bg-purple-500/10 ring-1 ring-purple-500/40" : ""
                  }`}
                  onClick={() => setClientType(ct.value)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-start gap-3">
                      <div className={`p-2 rounded-lg ${selected ? "bg-purple-500/20" : "bg-muted"}`}>
                        <Icon className={`h-5 w-5 ${selected ? "text-purple-400" : "text-muted-foreground"}`} />
                      </div>
                      <div>
                        <p className="font-medium text-sm">{ct.label}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{ct.desc}</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>
      )}

      {/* Step 2: Org Profile */}
      {step === "org_profile" && (
        <div className="space-y-6">
          <h2 className="text-lg font-semibold">Organization Profile</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Organization Name *</Label>
              <Input
                placeholder="Acme Corporation"
                value={customerName}
                onChange={e => setCustomerName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Sector *</Label>
              <Select value={sector} onValueChange={setSector}>
                <SelectTrigger>
                  <SelectValue placeholder="Select sector..." />
                </SelectTrigger>
                <SelectContent>
                  {SECTORS.map(s => (
                    <SelectItem key={s} value={s}>{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label>Critical Business Functions</Label>
            <p className="text-xs text-muted-foreground">Select functions critical to this organization. This drives BIA scoring.</p>
            <div className="flex flex-wrap gap-2">
              {CRITICAL_FUNCTIONS.map(f => (
                <Badge
                  key={f}
                  variant={criticalFunctions.includes(f) ? "default" : "outline"}
                  className={`cursor-pointer transition-all ${
                    criticalFunctions.includes(f) ? "bg-purple-500 hover:bg-purple-600" : "hover:border-purple-500/50"
                  }`}
                  onClick={() => toggleFunction(f)}
                >
                  {f.replace(/_/g, " ")}
                </Badge>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <Label>Compliance Requirements</Label>
            <div className="flex flex-wrap gap-2">
              {COMPLIANCE_FLAGS.map(f => (
                <Badge
                  key={f}
                  variant={complianceFlags.includes(f) ? "default" : "outline"}
                  className={`cursor-pointer transition-all ${
                    complianceFlags.includes(f) ? "bg-blue-500 hover:bg-blue-600" : "hover:border-blue-500/50"
                  }`}
                  onClick={() => toggleCompliance(f)}
                >
                  {f}
                </Badge>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <Label>Notes (optional)</Label>
            <Textarea
              placeholder="Any additional context about the organization, known infrastructure, or specific areas of concern..."
              value={notes}
              onChange={e => setNotes(e.target.value)}
              rows={3}
            />
          </div>
        </div>
      )}

      {/* Step 3: Domains */}
      {step === "domains" && (
        <div className="space-y-6">
          <h2 className="text-lg font-semibold">Target Domains</h2>
          <div className="space-y-2">
            <Label>Primary Domain *</Label>
            <Input
              placeholder="example.com"
              value={primaryDomain}
              onChange={e => setPrimaryDomain(e.target.value.trim().toLowerCase())}
            />
            <p className="text-xs text-muted-foreground">The main domain to analyze. Subdomains will be inferred automatically.</p>
          </div>

          <div className="space-y-2">
            <Label>Additional Domains</Label>
            <div className="flex gap-2">
              <Input
                placeholder="subsidiary.com"
                value={newDomain}
                onChange={e => setNewDomain(e.target.value)}
                onKeyDown={e => e.key === "Enter" && addDomain()}
              />
              <Button variant="outline" onClick={addDomain} disabled={!newDomain.trim()}>
                <Plus className="h-4 w-4" />
              </Button>
            </div>
            {additionalDomains.length > 0 && (
              <div className="flex flex-wrap gap-2 mt-2">
                {additionalDomains.map(d => (
                  <Badge key={d} variant="secondary" className="gap-1">
                    {d}
                    <X className="h-3 w-3 cursor-pointer hover:text-destructive" onClick={() => removeDomain(d)} />
                  </Badge>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Step 4: Review */}
      {step === "review" && (
        <div className="space-y-6">
          <h2 className="text-lg font-semibold">Review & Launch Pipeline</h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-muted-foreground">Organization</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <p className="font-semibold">{customerName}</p>
                <div className="flex gap-2">
                  <Badge variant="outline">{CLIENT_TYPES.find(c => c.value === clientType)?.label}</Badge>
                  <Badge variant="outline">{sector}</Badge>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-muted-foreground">Target Domains</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <p className="font-mono font-semibold">{primaryDomain}</p>
                {additionalDomains.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {additionalDomains.map(d => (
                      <Badge key={d} variant="secondary" className="font-mono text-xs">{d}</Badge>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {criticalFunctions.length > 0 && (
            <div className="space-y-2">
              <p className="text-sm font-medium text-muted-foreground">Critical Functions</p>
              <div className="flex flex-wrap gap-2">
                {criticalFunctions.map(f => (
                  <Badge key={f} className="bg-purple-500/20 text-purple-400">{f.replace(/_/g, " ")}</Badge>
                ))}
              </div>
            </div>
          )}

          {complianceFlags.length > 0 && (
            <div className="space-y-2">
              <p className="text-sm font-medium text-muted-foreground">Compliance</p>
              <div className="flex flex-wrap gap-2">
                {complianceFlags.map(f => (
                  <Badge key={f} className="bg-blue-500/20 text-blue-400">{f}</Badge>
                ))}
              </div>
            </div>
          )}

          {/* Pipeline stages preview */}
          <Card className="border-purple-500/30 bg-purple-500/5">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Zap className="h-4 w-4 text-purple-400" />
                Pipeline Stages
              </CardTitle>
              <CardDescription>The following analysis will be performed</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {[
                  { icon: Search, label: "Passive Discovery", desc: "LLM-inferred subdomains, services, tech stack" },
                  { icon: Shield, label: "Asset Classification", desc: "SSO, mail, API, payment, VPN identification" },
                  { icon: Target, label: "CARVER+SHOCK BIA", desc: "Mission-aware business impact scoring" },
                  { icon: AlertTriangle, label: "Hybrid Risk Scoring", desc: "CVSS + mission impact + context fusion" },
                  { icon: Crosshair, label: "Campaign Design", desc: "Auto-tailored Caldera & GoPhish campaigns" },
                  { icon: Brain, label: "Threat Modeling", desc: "Executive summary & attack path analysis" },
                ].map(s => (
                  <div key={s.label} className="flex items-start gap-2 p-2 rounded-lg bg-background/50">
                    <s.icon className="h-4 w-4 text-purple-400 mt-0.5 shrink-0" />
                    <div>
                      <p className="text-sm font-medium">{s.label}</p>
                      <p className="text-xs text-muted-foreground">{s.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {(startScan.error || pipelineError) && (
            <Card className="border-destructive bg-destructive/10">
              <CardContent className="p-4">
                <p className="text-sm text-destructive flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" />
                  {pipelineError || startScan.error?.message}
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Running State */}
      {step === "running" && (
        <Card className="border-purple-500/30">
          <CardContent className="p-12 flex flex-col items-center justify-center text-center space-y-6">
            <div className="relative">
              <div className="absolute inset-0 animate-ping rounded-full bg-purple-500/20 w-20 h-20" />
              <div className="relative bg-purple-500/10 rounded-full p-5">
                <Brain className="h-10 w-10 text-purple-400 animate-pulse" />
              </div>
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold">Running Domain Intelligence Pipeline</h2>
              <p className="text-muted-foreground max-w-md">
                Analyzing <span className="font-mono text-purple-400">{primaryDomain}</span> across multiple stages.
                This typically takes 60-120 seconds.
              </p>
            </div>
            <div className="w-full max-w-sm space-y-2">
              <Progress value={Math.max(5, (pipelineStage / 5) * 100)} className="h-2" />
              <p className="text-xs text-muted-foreground text-center">
                {scanStatusQuery.data?.status === "discovering" ? "Discovering assets..." :
                 scanStatusQuery.data?.status === "analyzing" ? "Analyzing & scoring assets..." :
                 scanStatusQuery.data?.status === "scoring" ? "Computing hybrid risk scores..." :
                 scanStatusQuery.data?.status === "recommending" ? "Generating campaign recommendations..." :
                 "Initializing pipeline..."}
              </p>
            </div>
            <div className="space-y-3 w-full max-w-sm">
              {[
                { label: "Passive Discovery", stage: 1 },
                { label: "Asset Classification & BIA", stage: 2 },
                { label: "Hybrid Risk Scoring", stage: 3 },
                { label: "Campaign Recommendations", stage: 4 },
                { label: "Threat Model Generation", stage: 5 },
              ].map((s) => (
                <div key={s.label} className={`flex items-center gap-3 transition-opacity ${pipelineStage >= s.stage ? "opacity-100" : "opacity-40"}`}>
                  {pipelineStage > s.stage ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  ) : pipelineStage === s.stage ? (
                    <Loader2 className="h-4 w-4 animate-spin text-purple-400" />
                  ) : (
                    <div className="h-4 w-4 rounded-full border border-muted-foreground/30" />
                  )}
                  <span className={`text-sm ${pipelineStage >= s.stage ? "text-foreground" : "text-muted-foreground"}`}>{s.label}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Complete State */}
      {step === "complete" && scanId && (
        <Card className="border-emerald-500/30">
          <CardContent className="p-12 flex flex-col items-center justify-center text-center space-y-6">
            <div className="bg-emerald-500/10 rounded-full p-5">
              <CheckCircle2 className="h-10 w-10 text-emerald-400" />
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold">Pipeline Complete</h2>
              <p className="text-muted-foreground">
                Domain intelligence analysis for <span className="font-mono text-emerald-400">{primaryDomain}</span> is ready.
              </p>
            </div>
            <div className="flex gap-3">
              <Button onClick={() => navigate(`/domain-intel/${scanId}`)}>
                <Target className="h-4 w-4 mr-2" />
                View Results
              </Button>
              <Button variant="outline" onClick={() => {
                setStep("client_type");
                setClientType("");
                setCustomerName("");
                setSector("");
                setPrimaryDomain("");
                setAdditionalDomains([]);
                setCriticalFunctions([]);
                setComplianceFlags([]);
                setNotes("");
                setScanId(null);
              }}>
                Start New Scan
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Navigation Buttons */}
      {step !== "running" && step !== "complete" && (
        <div className="flex justify-between pt-4 border-t border-border">
          <Button
            variant="outline"
            onClick={prevStep}
            disabled={step === "client_type"}
          >
            <ChevronLeft className="h-4 w-4 mr-1" />
            Back
          </Button>
          {step === "review" ? (
            <Button
              onClick={handleStartScan}
              disabled={startScan.isPending}
              className="bg-purple-600 hover:bg-purple-700"
            >
              {startScan.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Zap className="h-4 w-4 mr-2" />
              )}
              Launch Pipeline
            </Button>
          ) : (
            <Button onClick={nextStep} disabled={!canProceed}>
              Next
              <ChevronRight className="h-4 w-4 ml-1" />
            </Button>
          )}
        </div>
      )}

      {/* Past Scans Quick List */}
      {step === "client_type" && scansQuery.data && scansQuery.data.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-medium text-muted-foreground">Recent Scans</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {scansQuery.data.slice(0, 6).map((scan: any) => {
              const output = scan.pipelineOutput as any;
              const riskScore = output?.riskScore || scan.overallRiskScore || 0;
              const assetCount = output?.assets?.length || scan.totalAssets || 0;
              const findingCount = output?.postureFindings?.length || 0;
              const confirmedCount = output?.postureFindings?.filter((f: any) => f.corroborationTier === 'confirmed').length || 0;
              const probableCount = output?.postureFindings?.filter((f: any) => f.corroborationTier === 'probable').length || 0;
              const potentialCount = output?.postureFindings?.filter((f: any) => f.corroborationTier === 'potential').length || 0;
              return (
                <Card
                  key={scan.id}
                  className="cursor-pointer hover:border-purple-500/50 transition-all"
                  onClick={() => navigate(`/domain-intel/${scan.id}`)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-mono text-sm font-semibold">{scan.primaryDomain}</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          {scan.clientType?.toUpperCase() || 'SCAN'} &middot; Risk: <span className={riskScore >= 70 ? 'text-red-400 font-bold' : riskScore >= 40 ? 'text-orange-400 font-bold' : 'text-green-400 font-bold'}>{riskScore || 'N/A'}</span>
                        </p>
                      </div>
                      <Badge variant={
                        scan.status === "completed" ? "default" :
                        scan.status === "failed" ? "destructive" : "secondary"
                      } className={scan.status === "completed" ? "bg-emerald-500/20 text-emerald-400" : ""}>
                        {scan.status}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                      <span className="text-[10px] bg-muted px-1.5 py-0.5 rounded">{assetCount} assets</span>
                      {findingCount > 0 && <span className="text-[10px] bg-muted px-1.5 py-0.5 rounded">{findingCount} findings</span>}
                      {confirmedCount > 0 && <span className="text-[10px] bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">{confirmedCount} confirmed</span>}
                      {probableCount > 0 && <span className="text-[10px] bg-orange-500/20 text-orange-400 px-1.5 py-0.5 rounded">{probableCount} probable</span>}
                      {potentialCount > 0 && <span className="text-[10px] bg-muted/60 text-muted-foreground px-1.5 py-0.5 rounded">{potentialCount} potential</span>}
                    </div>
                    <div className="flex items-center justify-between mt-2 pt-2 border-t border-border">
                      <span className="text-[10px] text-muted-foreground">
                        {scan.createdAt ? new Date(scan.createdAt).toLocaleDateString() : ''}
                      </span>
                      <span className="text-[10px] text-purple-400 font-medium">View Results →</span>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
