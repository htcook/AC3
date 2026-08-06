import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import {
  Download,
  Shield,
  Server,
  Container,
  GitBranch,
  FileText,
  Copy,
  CheckCircle2,
  AlertTriangle,
  Cloud,
  Lock,
  Eye,
  Loader2,
  Info,
} from "lucide-react";

// ─── CloudFormation Template Generator ──────────────────────────────────────

function generateExternalId(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  let result = "ac3-";
  for (let i = 0; i < 28; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

interface OnboardingConfig {
  customerName: string;
  customerAccountId: string;
  externalId: string;
  enableCSPM: boolean;
  enableContainerScanning: boolean;
  enableCodePipelineCallback: boolean;
  enableCloudWatchLogs: boolean;
}

const MODULE_INFO = [
  {
    key: "enableCSPM" as const,
    label: "CSPM Assessment",
    description: "Read-only access to IAM, S3, CloudTrail, VPC, KMS for Prowler-based security posture assessment",
    icon: Shield,
    default: true,
  },
  {
    key: "enableContainerScanning" as const,
    label: "Container Scanning",
    description: "Read-only ECR access for container image vulnerability, misconfiguration, and secrets scanning",
    icon: Container,
    default: true,
  },
  {
    key: "enableCodePipelineCallback" as const,
    label: "CodePipeline Callback",
    description: "Allows AC3 to report scan results back to CodePipeline jobs (PutJobSuccessResult/PutJobFailureResult)",
    icon: GitBranch,
    default: true,
  },
  {
    key: "enableCloudWatchLogs" as const,
    label: "CloudWatch Logs",
    description: "Read-only log access for SOC monitoring, threat hunting, and SIEM integration",
    icon: FileText,
    default: false,
  },
];

export default function CustomerOnboarding() {
  const [config, setConfig] = useState<OnboardingConfig>({
    customerName: "",
    customerAccountId: "",
    externalId: generateExternalId(),
    enableCSPM: true,
    enableContainerScanning: true,
    enableCodePipelineCallback: true,
    enableCloudWatchLogs: false,
  });
  const [copied, setCopied] = useState<string | null>(null);
  const [showExternalId, setShowExternalId] = useState(false);

  const generateTemplate = trpc.onboarding.generateCloudFormation.useMutation({
    onSuccess: (data) => {
      // Download the YAML file
      const blob = new Blob([data.template], { type: "application/x-yaml" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = data.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success("CloudFormation template downloaded");
    },
    onError: (err) => toast.error(err.message),
  });

  const accountIdValid = /^\d{12}$/.test(config.customerAccountId);
  const nameValid = config.customerName.trim().length >= 2;
  const canDownload = accountIdValid && nameValid;

  const enabledModuleCount = useMemo(() => {
    let count = 1; // Environment Discovery is always on
    if (config.enableCSPM) count++;
    if (config.enableContainerScanning) count++;
    if (config.enableCodePipelineCallback) count++;
    if (config.enableCloudWatchLogs) count++;
    return count;
  }, [config]);

  const deployCommand = useMemo(() => {
    const params = [
      `AC3AccountId=808038814732`,
      `ExternalId=${config.externalId}`,
    ];
    if (!config.enableCSPM) params.push("EnableCSPM=false");
    if (!config.enableContainerScanning) params.push("EnableContainerScanning=false");
    if (!config.enableCodePipelineCallback) params.push("EnableCodePipelineCallback=false");
    if (config.enableCloudWatchLogs) params.push("EnableCloudWatchLogs=true");

    return `aws cloudformation deploy \\
  --template-file ac3-customer-cross-account-role.yaml \\
  --stack-name ac3-cross-account-role \\
  --parameter-overrides ${params.join(" ")} \\
  --capabilities CAPABILITY_NAMED_IAM`;
  }, [config]);

  const handleCopy = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(label);
    toast.success(`${label} copied to clipboard`);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleDownload = () => {
    generateTemplate.mutate({
      customerName: config.customerName.trim(),
      customerAccountId: config.customerAccountId,
      externalId: config.externalId,
      enableCSPM: config.enableCSPM,
      enableContainerScanning: config.enableContainerScanning,
      enableCodePipelineCallback: config.enableCodePipelineCallback,
      enableCloudWatchLogs: config.enableCloudWatchLogs,
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3 p-4 bg-primary/5 border border-primary/20 rounded-lg">
        <Cloud className="h-8 w-8 text-primary" />
        <div>
          <h2 className="text-lg font-semibold">AWS Cross-Account Role Setup</h2>
          <p className="text-sm text-muted-foreground">
            Generate a CloudFormation template for customers to deploy in their AWS account.
            The template creates a least-privilege IAM role that AC3 assumes via STS for
            environment discovery, CSPM assessment, container scanning, and CI/CD integration.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column — Configuration */}
        <div className="space-y-6">
          {/* Customer Details */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Server className="h-4 w-4" />
                Customer Details
              </CardTitle>
              <CardDescription>
                Identify the customer account for this onboarding
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="customerName">Customer Name</Label>
                <Input
                  id="customerName"
                  value={config.customerName}
                  onChange={(e) => setConfig((c) => ({ ...c, customerName: e.target.value }))}
                  placeholder="e.g., Acme Corp"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="customerAccountId">AWS Account ID</Label>
                <Input
                  id="customerAccountId"
                  value={config.customerAccountId}
                  onChange={(e) => {
                    const val = e.target.value.replace(/\D/g, "").slice(0, 12);
                    setConfig((c) => ({ ...c, customerAccountId: val }));
                  }}
                  placeholder="123456789012"
                  maxLength={12}
                />
                {config.customerAccountId.length > 0 && !accountIdValid && (
                  <p className="text-xs text-red-400 flex items-center gap-1">
                    <AlertTriangle className="h-3 w-3" /> Must be exactly 12 digits
                  </p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="externalId" className="flex items-center gap-2">
                  External ID (Confused Deputy Prevention)
                  <button
                    onClick={() => setShowExternalId(!showExternalId)}
                    className="text-muted-foreground hover:text-foreground"
                  >
                    <Eye className="h-3.5 w-3.5" />
                  </button>
                </Label>
                <div className="flex gap-2">
                  <Input
                    id="externalId"
                    value={showExternalId ? config.externalId : "••••••••••••••••••••••••••••••••"}
                    readOnly
                    className="font-mono text-sm"
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleCopy(config.externalId, "External ID")}
                  >
                    {copied === "External ID" ? <CheckCircle2 className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setConfig((c) => ({ ...c, externalId: generateExternalId() }))}
                  >
                    Regenerate
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Auto-generated unique ID. Store this — you'll need it when configuring the customer's
                  AWS connector in AC3.
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Permission Modules */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Lock className="h-4 w-4" />
                Permission Modules
                <Badge variant="secondary" className="ml-auto">{enabledModuleCount} of 5 enabled</Badge>
              </CardTitle>
              <CardDescription>
                Toggle which capabilities the cross-account role should include.
                Environment Discovery (EC2, ELB, API Gateway, CloudFront, Lambda, ECS) is always enabled.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Always-on module */}
              <div className="flex items-start gap-3 p-3 bg-muted/30 rounded-lg opacity-80">
                <Server className="h-5 w-5 text-primary mt-0.5" />
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">Environment Discovery</span>
                    <Badge variant="outline" className="text-xs">Always On</Badge>
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Read-only access to EC2, ELB, API Gateway, CloudFront, Lambda, and ECS for
                    infrastructure mapping and attack surface enumeration
                  </p>
                </div>
              </div>

              <Separator />

              {/* Toggleable modules */}
              {MODULE_INFO.map((mod) => {
                const Icon = mod.icon;
                const enabled = config[mod.key];
                return (
                  <div key={mod.key} className="flex items-start gap-3 p-3 rounded-lg hover:bg-muted/20 transition-colors">
                    <Icon className={`h-5 w-5 mt-0.5 ${enabled ? "text-primary" : "text-muted-foreground"}`} />
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className={`text-sm font-medium ${enabled ? "" : "text-muted-foreground"}`}>
                          {mod.label}
                        </span>
                        <Switch
                          checked={enabled}
                          onCheckedChange={(checked) =>
                            setConfig((c) => ({ ...c, [mod.key]: checked }))
                          }
                        />
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">{mod.description}</p>
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </div>

        {/* Right Column — Output */}
        <div className="space-y-6">
          {/* Download Card */}
          <Card className="border-primary/30">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Download className="h-4 w-4" />
                Download Template
              </CardTitle>
              <CardDescription>
                Generate and download the CloudFormation YAML with your configuration baked in
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button
                onClick={handleDownload}
                disabled={!canDownload || generateTemplate.isPending}
                className="w-full"
                size="lg"
              >
                {generateTemplate.isPending ? (
                  <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Generating...</>
                ) : (
                  <><Download className="h-4 w-4 mr-2" /> Download CloudFormation Template</>
                )}
              </Button>
              {!canDownload && (
                <p className="text-xs text-muted-foreground text-center">
                  Fill in customer name and a valid 12-digit AWS account ID to enable download
                </p>
              )}
            </CardContent>
          </Card>

          {/* Deploy Command */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <FileText className="h-4 w-4" />
                Deploy Command
              </CardTitle>
              <CardDescription>
                Customer runs this in their AWS account after downloading the template
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="relative">
                <pre className="bg-muted/50 border rounded-lg p-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap">
                  {deployCommand}
                </pre>
                <Button
                  variant="ghost"
                  size="sm"
                  className="absolute top-2 right-2"
                  onClick={() => handleCopy(deployCommand, "Deploy command")}
                >
                  {copied === "Deploy command" ? (
                    <CheckCircle2 className="h-4 w-4 text-green-500" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* What Gets Created */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Info className="h-4 w-4" />
                What Gets Created
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 text-sm">
                <div className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                  <div>
                    <span className="font-medium">IAM Role</span>
                    <span className="text-muted-foreground"> — <code className="text-xs">ac3-cross-account-role</code> with trust policy scoped to AC3 account + external ID</span>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                  <div>
                    <span className="font-medium">Environment Discovery Policy</span>
                    <span className="text-muted-foreground"> — Read-only EC2, ELB, API Gateway, CloudFront, Lambda, ECS</span>
                  </div>
                </div>
                {config.enableCSPM && (
                  <div className="flex items-start gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                    <div>
                      <span className="font-medium">CSPM Assessment Policy</span>
                      <span className="text-muted-foreground"> — Read-only IAM, S3, CloudTrail, VPC, KMS, Config, GuardDuty</span>
                    </div>
                  </div>
                )}
                {config.enableContainerScanning && (
                  <div className="flex items-start gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                    <div>
                      <span className="font-medium">Container Scanning Policy</span>
                      <span className="text-muted-foreground"> — Read-only ECR repository and image access</span>
                    </div>
                  </div>
                )}
                {config.enableCodePipelineCallback && (
                  <div className="flex items-start gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                    <div>
                      <span className="font-medium">CodePipeline Callback Policy</span>
                      <span className="text-muted-foreground"> — PutJobSuccessResult/PutJobFailureResult for CI/CD integration</span>
                    </div>
                  </div>
                )}
                {config.enableCloudWatchLogs && (
                  <div className="flex items-start gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                    <div>
                      <span className="font-medium">CloudWatch Logs Policy</span>
                      <span className="text-muted-foreground"> — Read-only log group and stream access for SIEM integration</span>
                    </div>
                  </div>
                )}

                <Separator className="my-3" />

                <div className="flex items-start gap-2">
                  <Shield className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />
                  <div>
                    <span className="font-medium text-amber-400">Security Controls</span>
                    <ul className="text-xs text-muted-foreground mt-1 space-y-0.5 list-disc list-inside">
                      <li>Confused deputy prevention via external ID</li>
                      <li>All permissions are read-only (except CodePipeline callbacks)</li>
                      <li>Partition-aware ARNs (GovCloud compatible)</li>
                      <li>1-hour maximum session duration</li>
                      <li>Resource tagging for audit trail</li>
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
