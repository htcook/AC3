import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Cloud, Shield, CheckCircle, XCircle, AlertTriangle, ArrowRight, ArrowLeft,
  Loader2, Server, Lock, Eye, EyeOff, Copy, GitBranch, Zap, Search,
  ChevronRight, ExternalLink, Info, RefreshCw, Package, Key
} from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface AuthField {
  key: string;
  label: string;
  placeholder: string;
  required?: boolean;
  sensitive?: boolean;
  multiline?: boolean;
  helpText?: string;
  type?: string;
}

interface AuthMethod {
  id: string;
  label: string;
  description: string;
  recommended: boolean;
  fields: AuthField[];
  iamPolicyJson?: string;
  trustPolicyJson?: string;
  setupSteps?: string[];
}

type WizardStep = "provider" | "auth" | "test" | "discover" | "pipeline" | "complete";

const STEPS: { id: WizardStep; label: string; icon: React.ReactNode }[] = [
  { id: "provider", label: "Select Provider", icon: <Cloud className="w-4 h-4" /> },
  { id: "auth", label: "Configure Auth", icon: <Key className="w-4 h-4" /> },
  { id: "test", label: "Test Connection", icon: <Shield className="w-4 h-4" /> },
  { id: "discover", label: "Discover Resources", icon: <Search className="w-4 h-4" /> },
  { id: "pipeline", label: "Link Pipeline", icon: <GitBranch className="w-4 h-4" /> },
  { id: "complete", label: "Complete", icon: <CheckCircle className="w-4 h-4" /> },
];

const PROVIDER_ICONS: Record<string, { color: string; bg: string; label: string }> = {
  aws: { color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/30", label: "Amazon Web Services" },
  azure: { color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/30", label: "Microsoft Azure" },
  gcp: { color: "text-green-400", bg: "bg-green-500/10 border-green-500/30", label: "Google Cloud Platform" },
};

// ─── Step Progress Bar ─────────────────────────────────────────────────────────

function StepProgressBar({ currentStep }: { currentStep: WizardStep }) {
  const currentIndex = STEPS.findIndex(s => s.id === currentStep);
  const progress = ((currentIndex + 1) / STEPS.length) * 100;

  return (
    <div className="mb-8">
      <div className="flex items-center justify-between mb-3">
        {STEPS.map((step, i) => {
          const isActive = i === currentIndex;
          const isComplete = i < currentIndex;
          return (
            <div key={step.id} className="flex items-center gap-1.5">
              <div className={`
                flex items-center justify-center w-8 h-8 rounded-full text-xs font-bold transition-all
                ${isComplete ? "bg-emerald-500/20 text-emerald-400 ring-1 ring-emerald-500/40" : ""}
                ${isActive ? "bg-primary/20 text-primary ring-2 ring-primary/50 scale-110" : ""}
                ${!isComplete && !isActive ? "bg-muted/50 text-muted-foreground/50" : ""}
              `}>
                {isComplete ? <CheckCircle className="w-4 h-4" /> : step.icon}
              </div>
              <span className={`text-xs font-medium hidden lg:inline ${isActive ? "text-foreground" : "text-muted-foreground/60"}`}>
                {step.label}
              </span>
              {i < STEPS.length - 1 && (
                <ChevronRight className={`w-4 h-4 mx-1 ${isComplete ? "text-emerald-500/50" : "text-muted-foreground/20"}`} />
              )}
            </div>
          );
        })}
      </div>
      <Progress value={progress} className="h-1.5" />
    </div>
  );
}

// ─── Step 1: Provider Selection ────────────────────────────────────────────────

function ProviderStep({
  onSelect,
}: {
  onSelect: (provider: string) => void;
}) {
  const { data: providers, isLoading } = trpc.cloudSetupWizard.listProviders.useQuery();
  const { data: wizardStatus } = trpc.cloudSetupWizard.getWizardStatus.useQuery({});

  return (
    <div className="space-y-6">
      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold mb-2">Connect Your Cloud Environment</h2>
        <p className="text-muted-foreground max-w-xl mx-auto">
          Select your cloud provider to begin the guided setup. AC3 will securely connect to your environment
          for security scanning, configuration auditing, and DevSecOps pipeline integration.
        </p>
      </div>

      {wizardStatus && wizardStatus.totalCredentials > 0 && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-sm">
          <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>You have {wizardStatus.totalCredentials} cloud credential(s) and {wizardStatus.totalPipelines} pipeline(s) configured.</span>
        </div>
      )}

      {isLoading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {providers?.map(p => {
            const style = PROVIDER_ICONS[p.id] || { color: "text-foreground", bg: "bg-muted", label: p.name };
            return (
              <Card
                key={p.id}
                className={`cursor-pointer transition-all hover:scale-[1.02] hover:shadow-lg border ${style.bg}`}
                onClick={() => onSelect(p.id)}
              >
                <CardContent className="pt-6 pb-4 text-center space-y-3">
                  <Cloud className={`w-12 h-12 mx-auto ${style.color}`} />
                  <h3 className="font-bold text-lg">{p.name}</h3>
                  <p className="text-sm text-muted-foreground">
                    {p.authMethodCount} auth methods | {p.regionCount} regions
                  </p>
                  <Badge variant="outline" className="text-xs">
                    Recommended: {p.recommendedAuth}
                  </Badge>
                  <Button variant="ghost" className="w-full mt-2 group">
                    Get Started <ArrowRight className="w-4 h-4 ml-1 group-hover:translate-x-1 transition-transform" />
                  </Button>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Step 2: Auth Configuration ────────────────────────────────────────────────

function AuthStep({
  provider,
  onBack,
  onNext,
}: {
  provider: string;
  onBack: () => void;
  onNext: (authMethod: string, credentials: Record<string, string>, region: string) => void;
}) {
  const { data: meta, isLoading } = trpc.cloudSetupWizard.getProviderMetadata.useQuery({
    provider: provider as "aws" | "azure" | "gcp",
  });

  const [selectedAuth, setSelectedAuth] = useState<string>("");
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [region, setRegion] = useState("");
  const [showSensitive, setShowSensitive] = useState<Record<string, boolean>>({});
  const [showPolicy, setShowPolicy] = useState(false);

  const currentMethod = useMemo(
    () => meta?.authMethods.find(m => m.id === selectedAuth) as AuthMethod | undefined,
    [meta, selectedAuth]
  );

  // Auto-select recommended method
  if (meta && !selectedAuth) {
    const rec = meta.authMethods.find(m => m.recommended);
    if (rec) setSelectedAuth(rec.id);
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const style = PROVIDER_ICONS[provider];
  const allRequiredFilled = currentMethod?.fields
    .filter(f => f.required)
    .every(f => credentials[f.key]?.trim()) ?? false;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-4">
        <Cloud className={`w-6 h-6 ${style?.color}`} />
        <h2 className="text-xl font-bold">{meta?.name} — Authentication</h2>
      </div>

      {/* Auth method selection */}
      <div className="space-y-3">
        <Label className="text-sm font-semibold">Authentication Method</Label>
        <div className="grid gap-3">
          {meta?.authMethods.map(method => (
            <Card
              key={method.id}
              className={`cursor-pointer transition-all ${
                selectedAuth === method.id
                  ? "ring-2 ring-primary/50 bg-primary/5"
                  : "hover:bg-muted/30"
              }`}
              onClick={() => {
                setSelectedAuth(method.id);
                setCredentials({});
              }}
            >
              <CardContent className="py-3 px-4 flex items-start gap-3">
                <div className={`mt-0.5 w-4 h-4 rounded-full border-2 flex items-center justify-center shrink-0 ${
                  selectedAuth === method.id ? "border-primary bg-primary" : "border-muted-foreground/30"
                }`}>
                  {selectedAuth === method.id && <div className="w-1.5 h-1.5 rounded-full bg-white" />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-sm">{method.label}</span>
                    {method.recommended && (
                      <Badge className="bg-emerald-500/20 text-emerald-400 text-[10px] px-1.5">Recommended</Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">{method.description}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Setup instructions (if available) */}
      {currentMethod?.setupSteps && (
        <Card className="bg-blue-500/5 border-blue-500/20">
          <CardContent className="py-3 px-4">
            <div className="flex items-center gap-2 mb-2">
              <Info className="w-4 h-4 text-blue-400" />
              <span className="text-sm font-semibold text-blue-400">Setup Instructions</span>
            </div>
            <ol className="text-xs text-muted-foreground space-y-1.5 list-decimal list-inside">
              {currentMethod.setupSteps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
          </CardContent>
        </Card>
      )}

      {/* IAM Policy (for AWS assume role) */}
      {currentMethod?.iamPolicyJson && (
        <div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowPolicy(!showPolicy)}
            className="text-xs text-muted-foreground"
          >
            {showPolicy ? "Hide" : "Show"} IAM Policy Template
          </Button>
          {showPolicy && (
            <div className="mt-2 space-y-2">
              <div className="relative">
                <Label className="text-xs text-muted-foreground">IAM Permission Policy</Label>
                <pre className="text-[10px] bg-muted/30 p-3 rounded-lg overflow-x-auto max-h-48 border">
                  {currentMethod.iamPolicyJson}
                </pre>
                <Button
                  variant="ghost"
                  size="sm"
                  className="absolute top-6 right-2"
                  onClick={() => {
                    navigator.clipboard.writeText(currentMethod.iamPolicyJson!);
                    toast.success("Policy copied");
                  }}
                >
                  <Copy className="w-3 h-3" />
                </Button>
              </div>
              {currentMethod.trustPolicyJson && (
                <div className="relative">
                  <Label className="text-xs text-muted-foreground">Trust Policy</Label>
                  <pre className="text-[10px] bg-muted/30 p-3 rounded-lg overflow-x-auto max-h-48 border">
                    {currentMethod.trustPolicyJson}
                  </pre>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="absolute top-6 right-2"
                    onClick={() => {
                      navigator.clipboard.writeText(currentMethod.trustPolicyJson!);
                      toast.success("Trust policy copied");
                    }}
                  >
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Credential fields */}
      {currentMethod && (
        <div className="space-y-4">
          <Label className="text-sm font-semibold">Credentials</Label>
          {currentMethod.fields.map(field => (
            <div key={field.key} className="space-y-1.5">
              <Label className="text-xs">
                {field.label}
                {field.required && <span className="text-red-400 ml-0.5">*</span>}
              </Label>
              {field.multiline ? (
                <Textarea
                  placeholder={field.placeholder}
                  value={credentials[field.key] || ""}
                  onChange={e => setCredentials(prev => ({ ...prev, [field.key]: e.target.value }))}
                  rows={6}
                  className="font-mono text-xs"
                />
              ) : (
                <div className="relative">
                  <Input
                    type={field.sensitive && !showSensitive[field.key] ? "password" : "text"}
                    placeholder={field.placeholder}
                    value={credentials[field.key] || ""}
                    onChange={e => setCredentials(prev => ({ ...prev, [field.key]: e.target.value }))}
                    className="font-mono text-xs pr-10"
                  />
                  {field.sensitive && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6 p-0"
                      onClick={() => setShowSensitive(prev => ({ ...prev, [field.key]: !prev[field.key] }))}
                    >
                      {showSensitive[field.key] ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    </Button>
                  )}
                </div>
              )}
              {field.helpText && (
                <p className="text-[10px] text-muted-foreground">{field.helpText}</p>
              )}
            </div>
          ))}

          {/* Region selection */}
          {meta?.regions && (
            <div className="space-y-1.5">
              <Label className="text-xs">Primary Region</Label>
              <Select value={region} onValueChange={setRegion}>
                <SelectTrigger className="text-xs">
                  <SelectValue placeholder="Select a region..." />
                </SelectTrigger>
                <SelectContent>
                  {meta.regions.map(r => (
                    <SelectItem key={r} value={r} className="text-xs">{r}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
        </div>
      )}

      <div className="flex justify-between pt-4">
        <Button variant="outline" onClick={onBack}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Back
        </Button>
        <Button
          disabled={!allRequiredFilled || !selectedAuth}
          onClick={() => onNext(selectedAuth, credentials, region || meta?.regions[0] || "")}
        >
          Test Connection <ArrowRight className="w-4 h-4 ml-1" />
        </Button>
      </div>
    </div>
  );
}

// ─── Step 3: Test Connection ───────────────────────────────────────────────────

function TestStep({
  provider,
  authMethod,
  credentials,
  region,
  onBack,
  onNext,
}: {
  provider: string;
  authMethod: string;
  credentials: Record<string, string>;
  region: string;
  onBack: () => void;
  onNext: (credentialName: string, credentialId: number) => void;
}) {
  const [testResult, setTestResult] = useState<any>(null);
  const [testing, setTesting] = useState(false);
  const [credentialName, setCredentialName] = useState("");
  const [storing, setStoring] = useState(false);

  const testMutation = trpc.cloudSetupWizard.testConnection.useMutation();
  const storeMutation = trpc.cloudSetupWizard.storeCredentials.useMutation();

  const runTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await testMutation.mutateAsync({
        provider: provider as "aws" | "azure" | "gcp",
        authMethod,
        credentials,
        region,
      });
      setTestResult(result);
      if (result.success) {
        toast.success("Connection successful!");
        // Auto-generate credential name
        if (!credentialName) {
          const provLabel = PROVIDER_ICONS[provider]?.label || provider;
          setCredentialName(`${provLabel} - ${authMethod.replace(/_/g, " ")}`);
        }
      } else {
        toast.error("Connection failed");
      }
    } catch (e: any) {
      setTestResult({ success: false, error: e.message });
      toast.error("Test failed");
    }
    setTesting(false);
  };

  const handleStore = async () => {
    if (!credentialName.trim()) {
      toast.error("Please enter a name for these credentials");
      return;
    }
    setStoring(true);
    try {
      const storeResult = await storeMutation.mutateAsync({
        provider: provider as "aws" | "azure" | "gcp",
        authMethod,
        credentials,
        credentialName: credentialName.trim(),
        region,
      });
      toast.success("Credentials stored securely");
      onNext(credentialName.trim(), storeResult.credentialId);
    } catch (e: any) {
      toast.error(e.message || "Failed to store credentials");
    }
    setStoring(false);
  };

  const style = PROVIDER_ICONS[provider];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-4">
        <Shield className={`w-6 h-6 ${style?.color}`} />
        <h2 className="text-xl font-bold">Test Connection</h2>
      </div>

      <Card className="bg-muted/20">
        <CardContent className="py-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">{PROVIDER_ICONS[provider]?.label}</p>
              <p className="text-xs text-muted-foreground">{authMethod.replace(/_/g, " ")} | {region}</p>
            </div>
            <Button
              onClick={runTest}
              disabled={testing}
              variant={testResult?.success ? "outline" : "default"}
            >
              {testing ? (
                <><Loader2 className="w-4 h-4 mr-1 animate-spin" /> Testing...</>
              ) : testResult ? (
                <><RefreshCw className="w-4 h-4 mr-1" /> Retest</>
              ) : (
                <><Zap className="w-4 h-4 mr-1" /> Run Test</>
              )}
            </Button>
          </div>

          {testResult && (
            <div className={`p-3 rounded-lg border ${
              testResult.success
                ? "bg-emerald-500/10 border-emerald-500/20"
                : "bg-red-500/10 border-red-500/20"
            }`}>
              <div className="flex items-center gap-2 mb-1">
                {testResult.success ? (
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-400" />
                )}
                <span className="text-sm font-medium">
                  {testResult.success ? "Connection Successful" : "Connection Failed"}
                </span>
                {testResult.latencyMs && (
                  <Badge variant="outline" className="text-[10px] ml-auto">{testResult.latencyMs}ms</Badge>
                )}
              </div>
              {testResult.identity && (
                <p className="text-xs text-muted-foreground mt-1 font-mono">{testResult.identity}</p>
              )}
              {testResult.error && (
                <p className="text-xs text-red-400 mt-1">{testResult.error}</p>
              )}
              {testResult.troubleshooting && testResult.troubleshooting.length > 0 && (
                <div className="mt-2 space-y-1">
                  <p className="text-xs font-medium text-amber-400 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> Troubleshooting Tips
                  </p>
                  <ul className="text-[10px] text-muted-foreground space-y-0.5 list-disc list-inside">
                    {testResult.troubleshooting.map((tip: string, i: number) => (
                      <li key={i}>{tip}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {testResult?.success && (
        <Card>
          <CardContent className="py-4 space-y-3">
            <div className="flex items-center gap-2 mb-1">
              <Lock className="w-4 h-4 text-primary" />
              <span className="text-sm font-semibold">Save Credentials</span>
            </div>
            <p className="text-xs text-muted-foreground">
              Credentials are encrypted at rest with AES-256-GCM. Give them a descriptive name for easy identification.
            </p>
            <div className="space-y-1.5">
              <Label className="text-xs">Credential Name <span className="text-red-400">*</span></Label>
              <Input
                value={credentialName}
                onChange={e => setCredentialName(e.target.value)}
                placeholder="e.g., Production AWS Account"
                className="text-sm"
              />
            </div>
          </CardContent>
        </Card>
      )}

      <div className="flex justify-between pt-4">
        <Button variant="outline" onClick={onBack}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Back
        </Button>
        <Button
          disabled={!testResult?.success || !credentialName.trim() || storing}
          onClick={handleStore}
        >
          {storing ? (
            <><Loader2 className="w-4 h-4 mr-1 animate-spin" /> Storing...</>
          ) : (
            <>Save & Continue <ArrowRight className="w-4 h-4 ml-1" /></>
          )}
        </Button>
      </div>
    </div>
  );
}

// ─── Step 4: Discover Resources ────────────────────────────────────────────────

function DiscoverStep({
  credentialId,
  onBack,
  onNext,
}: {
  credentialId: number;
  onBack: () => void;
  onNext: (scanTypes: string[]) => void;
}) {
  const [discovering, setDiscovering] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [selectedScans, setSelectedScans] = useState<Set<string>>(new Set());

  const discoverMutation = trpc.cloudSetupWizard.discoverResources.useMutation();

  const runDiscovery = async () => {
    setDiscovering(true);
    try {
      const res = await discoverMutation.mutateAsync({ credentialId });
      setResult(res);
      // Auto-select default scan types
      const defaults = new Set(res.scanTypes.filter((s: any) => s.default).map((s: any) => s.id));
      setSelectedScans(defaults);
      toast.success("Resource discovery complete");
    } catch (e: any) {
      toast.error(e.message || "Discovery failed");
    }
    setDiscovering(false);
  };

  const toggleScan = (id: string) => {
    setSelectedScans(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-4">
        <Search className="w-6 h-6 text-primary" />
        <h2 className="text-xl font-bold">Discover Resources</h2>
      </div>

      <p className="text-sm text-muted-foreground">
        AC3 will enumerate resources in your cloud account to determine the scan scope.
        No changes are made to your environment during discovery.
      </p>

      {!result && (
        <div className="flex justify-center py-8">
          <Button onClick={runDiscovery} disabled={discovering} size="lg">
            {discovering ? (
              <><Loader2 className="w-5 h-5 mr-2 animate-spin" /> Discovering Resources...</>
            ) : (
              <><Search className="w-5 h-5 mr-2" /> Start Discovery</>
            )}
          </Button>
        </div>
      )}

      {result && (
        <>
          {/* Resource summary */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {result.resources.map((r: any, i: number) => (
              <Card key={i} className={r.category === "Error" ? "border-red-500/30 bg-red-500/5" : ""}>
                <CardContent className="py-3 px-4">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-muted-foreground">{r.category}</span>
                    {r.scannable && <Badge variant="outline" className="text-[10px]">Scannable</Badge>}
                  </div>
                  <p className="text-sm font-medium">{r.type}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {r.count === -1 ? "Access required for count" : `${r.count} found`}
                  </p>
                  {r.examples.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {r.examples.map((ex: string, j: number) => (
                        <Badge key={j} variant="secondary" className="text-[10px] font-mono">{ex}</Badge>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Scan type selection */}
          <div className="space-y-3">
            <Label className="text-sm font-semibold">Select Scan Types</Label>
            <div className="grid gap-2">
              {result.scanTypes.map((scan: any) => (
                <div
                  key={scan.id}
                  className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                    selectedScans.has(scan.id)
                      ? "bg-primary/5 border-primary/30"
                      : "bg-muted/10 border-border hover:bg-muted/20"
                  }`}
                  onClick={() => toggleScan(scan.id)}
                >
                  <Checkbox
                    checked={selectedScans.has(scan.id)}
                    onCheckedChange={() => toggleScan(scan.id)}
                  />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{scan.label}</span>
                      {scan.default && (
                        <Badge className="bg-blue-500/20 text-blue-400 text-[10px]">Default</Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">{scan.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <Button
            variant="ghost"
            size="sm"
            onClick={runDiscovery}
            disabled={discovering}
            className="text-xs"
          >
            <RefreshCw className={`w-3 h-3 mr-1 ${discovering ? "animate-spin" : ""}`} /> Re-run Discovery
          </Button>
        </>
      )}

      <div className="flex justify-between pt-4">
        <Button variant="outline" onClick={onBack}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Back
        </Button>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => onNext(Array.from(selectedScans))}>
            Skip Pipeline Setup <ArrowRight className="w-4 h-4 ml-1" />
          </Button>
          {result && (
            <Button onClick={() => onNext(Array.from(selectedScans))} disabled={selectedScans.size === 0}>
              Configure Pipeline <ArrowRight className="w-4 h-4 ml-1" />
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Step 5: Link Pipeline ─────────────────────────────────────────────────────

function PipelineStep({
  credentialId,
  scanTypes,
  onBack,
  onComplete,
}: {
  credentialId: number;
  scanTypes: string[];
  onBack: () => void;
  onComplete: (result: any) => void;
}) {
  const [pipelineName, setPipelineName] = useState("");
  const [cicdProvider, setCicdProvider] = useState("github_actions");
  const [targetUrl, setTargetUrl] = useState("");
  const [creating, setCreating] = useState(false);

  const createMutation = trpc.cloudSetupWizard.createLinkedPipeline.useMutation();

  const handleCreate = async () => {
    if (!pipelineName.trim()) {
      toast.error("Pipeline name is required");
      return;
    }
    setCreating(true);
    try {
      const result = await createMutation.mutateAsync({
        credentialId,
        pipelineName: pipelineName.trim(),
        cicdProvider: cicdProvider as any,
        targetUrl: targetUrl.trim() || undefined,
        scanTypes,
      });
      toast.success("Pipeline created!");
      onComplete(result);
    } catch (e: any) {
      toast.error(e.message || "Failed to create pipeline");
    }
    setCreating(false);
  };

  const CICD_PROVIDERS = [
    { value: "github_actions", label: "GitHub Actions" },
    { value: "gitlab_ci", label: "GitLab CI" },
    { value: "jenkins", label: "Jenkins" },
    { value: "azure_devops", label: "Azure DevOps" },
    { value: "custom", label: "Custom / AWS CodePipeline" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-4">
        <GitBranch className="w-6 h-6 text-primary" />
        <h2 className="text-xl font-bold">Link CI/CD Pipeline</h2>
      </div>

      <p className="text-sm text-muted-foreground">
        Create a pipeline that triggers security scans on every code push.
        AC3 will generate the YAML configuration for your CI/CD provider.
      </p>

      <div className="space-y-4">
        <div className="space-y-1.5">
          <Label className="text-xs">Pipeline Name <span className="text-red-400">*</span></Label>
          <Input
            value={pipelineName}
            onChange={e => setPipelineName(e.target.value)}
            placeholder="e.g., Production Security Gate"
            className="text-sm"
          />
        </div>

        <div className="space-y-1.5">
          <Label className="text-xs">CI/CD Provider</Label>
          <Select value={cicdProvider} onValueChange={setCicdProvider}>
            <SelectTrigger className="text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CICD_PROVIDERS.map(p => (
                <SelectItem key={p.value} value={p.value} className="text-sm">{p.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1.5">
          <Label className="text-xs">Target URL (optional)</Label>
          <Input
            value={targetUrl}
            onChange={e => setTargetUrl(e.target.value)}
            placeholder="https://staging.example.com"
            className="text-sm"
          />
          <p className="text-[10px] text-muted-foreground">
            The URL to scan. If provided, it will be added to the allowed domains list.
          </p>
        </div>

        <div className="space-y-1.5">
          <Label className="text-xs">Selected Scan Types</Label>
          <div className="flex flex-wrap gap-1.5">
            {scanTypes.map(st => (
              <Badge key={st} variant="secondary" className="text-xs">{st}</Badge>
            ))}
          </div>
        </div>
      </div>

      <div className="flex justify-between pt-4">
        <Button variant="outline" onClick={onBack}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Back
        </Button>
        <Button onClick={handleCreate} disabled={!pipelineName.trim() || creating}>
          {creating ? (
            <><Loader2 className="w-4 h-4 mr-1 animate-spin" /> Creating...</>
          ) : (
            <>Create Pipeline <ArrowRight className="w-4 h-4 ml-1" /></>
          )}
        </Button>
      </div>
    </div>
  );
}

// ─── Step 6: Complete ──────────────────────────────────────────────────────────

function CompleteStep({
  pipelineResult,
  onStartOver,
}: {
  pipelineResult: any;
  onStartOver: () => void;
}) {
  const [showSecret, setShowSecret] = useState(false);
  const [showYaml, setShowYaml] = useState(false);

  return (
    <div className="space-y-6">
      <div className="text-center mb-6">
        <div className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center mx-auto mb-4">
          <CheckCircle className="w-8 h-8 text-emerald-400" />
        </div>
        <h2 className="text-2xl font-bold">Setup Complete!</h2>
        <p className="text-muted-foreground mt-1">
          Your cloud environment is connected and a CI/CD pipeline has been created.
        </p>
      </div>

      {pipelineResult && (
        <div className="space-y-4">
          {/* Webhook URL */}
          <Card>
            <CardContent className="py-3 px-4 space-y-2">
              <Label className="text-xs font-semibold">Webhook URL</Label>
              <div className="flex items-center gap-2">
                <code className="text-xs bg-muted/30 p-2 rounded flex-1 font-mono break-all">
                  {pipelineResult.webhookUrl}
                </code>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    navigator.clipboard.writeText(pipelineResult.webhookUrl);
                    toast.success("Copied");
                  }}
                >
                  <Copy className="w-3 h-3" />
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Webhook Secret */}
          <Card>
            <CardContent className="py-3 px-4 space-y-2">
              <Label className="text-xs font-semibold">Webhook Secret</Label>
              <div className="flex items-center gap-2">
                <code className="text-xs bg-muted/30 p-2 rounded flex-1 font-mono">
                  {showSecret ? pipelineResult.webhookSecret : "ac3_whsec_" + "•".repeat(32)}
                </code>
                <Button variant="ghost" size="sm" onClick={() => setShowSecret(!showSecret)}>
                  {showSecret ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    navigator.clipboard.writeText(pipelineResult.webhookSecret);
                    toast.success("Secret copied");
                  }}
                >
                  <Copy className="w-3 h-3" />
                </Button>
              </div>
              <p className="text-[10px] text-amber-400 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                Save this secret now. It cannot be retrieved later (only regenerated).
              </p>
            </CardContent>
          </Card>

          {/* YAML Snippet */}
          <Card>
            <CardContent className="py-3 px-4 space-y-2">
              <div className="flex items-center justify-between">
                <Label className="text-xs font-semibold">CI/CD Configuration</Label>
                <Button variant="ghost" size="sm" onClick={() => setShowYaml(!showYaml)} className="text-xs">
                  {showYaml ? "Hide" : "Show"} YAML
                </Button>
              </div>
              {showYaml && (
                <div className="relative">
                  <pre className="text-[10px] bg-muted/30 p-3 rounded-lg overflow-x-auto max-h-64 border font-mono">
                    {pipelineResult.yamlSnippet}
                  </pre>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="absolute top-2 right-2"
                    onClick={() => {
                      navigator.clipboard.writeText(pipelineResult.yamlSnippet);
                      toast.success("YAML copied");
                    }}
                  >
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Scan types */}
          <Card>
            <CardContent className="py-3 px-4">
              <Label className="text-xs font-semibold mb-2 block">Enabled Scan Types</Label>
              <div className="flex flex-wrap gap-1.5">
                {pipelineResult.scanTypes.map((st: string) => (
                  <Badge key={st} className="bg-primary/20 text-primary text-xs">{st}</Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      <div className="flex justify-center gap-3 pt-4">
        <Button variant="outline" onClick={onStartOver}>
          <Cloud className="w-4 h-4 mr-1" /> Connect Another Cloud
        </Button>
        <Button asChild>
          <a href="/cicd-pipeline">
            <GitBranch className="w-4 h-4 mr-1" /> Go to CI/CD Pipeline
          </a>
        </Button>
      </div>
    </div>
  );
}

// ─── Main Wizard Page ──────────────────────────────────────────────────────────

export default function CloudSetupWizardPage() {
  const [step, setStep] = useState<WizardStep>("provider");
  const [provider, setProvider] = useState("");
  const [authMethod, setAuthMethod] = useState("");
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [region, setRegion] = useState("");
  const [credentialId, setCredentialId] = useState(0);
  const [scanTypes, setScanTypes] = useState<string[]>([]);
  const [pipelineResult, setPipelineResult] = useState<any>(null);

  const reset = () => {
    setStep("provider");
    setProvider("");
    setAuthMethod("");
    setCredentials({});
    setRegion("");
    setCredentialId(0);
    setScanTypes([]);
    setPipelineResult(null);
  };

  return (
    <AppShell>
      <div className="max-w-3xl mx-auto px-4 py-8">
        <StepProgressBar currentStep={step} />

        {step === "provider" && (
          <ProviderStep
            onSelect={(p) => {
              setProvider(p);
              setStep("auth");
            }}
          />
        )}

        {step === "auth" && (
          <AuthStep
            provider={provider}
            onBack={() => setStep("provider")}
            onNext={(am, creds, reg) => {
              setAuthMethod(am);
              setCredentials(creds);
              setRegion(reg);
              setStep("test");
            }}
          />
        )}

        {step === "test" && (
          <TestStep
            provider={provider}
            authMethod={authMethod}
            credentials={credentials}
            region={region}
            onBack={() => setStep("auth")}
            onNext={(name, id) => {
              setCredentialId(id);
              setStep("discover");
            }}
          />
        )}

        {step === "discover" && (
          <DiscoverStep
            credentialId={credentialId}
            onBack={() => setStep("test")}
            onNext={(types) => {
              setScanTypes(types);
              setStep("pipeline");
            }}
          />
        )}

        {step === "pipeline" && (
          <PipelineStep
            credentialId={credentialId}
            scanTypes={scanTypes}
            onBack={() => setStep("discover")}
            onComplete={(result) => {
              setPipelineResult(result);
              setStep("complete");
            }}
          />
        )}

        {step === "complete" && (
          <CompleteStep
            pipelineResult={pipelineResult}
            onStartOver={reset}
          />
        )}
      </div>
    </AppShell>
  );
}
