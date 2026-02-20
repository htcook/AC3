import AppShell from "@/components/AppShell";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { APT_SCENARIOS } from "@/data/apt-scenarios";
import { RANSOMWARE_PROFILES, type RansomwareAbilityProfile, type RansomwareIOC } from "@/data/ransomware-abilities";
import {
  Zap, Mail, Globe, Shield, AlertTriangle, CheckCircle2, XCircle,
  Loader2, Send, Eye, Code, FileText, Target, Skull, Search,
  ChevronRight, Sparkles, Download, Copy, ExternalLink
} from "lucide-react";
import { toast } from "sonner";

import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
type PhishingType = 'credential_harvest' | 'malware_delivery' | 'callback_phishing' | 'business_email_compromise' | 'mfa_fatigue';
type Sophistication = 'basic' | 'intermediate' | 'advanced';

const PHISHING_TYPES: { value: PhishingType; label: string; description: string; icon: React.ReactNode }[] = [
  { value: 'credential_harvest', label: 'Credential Harvest', description: 'Fake login pages to capture usernames & passwords', icon: <Target className="w-4 h-4" /> },
  { value: 'malware_delivery', label: 'Malware Delivery', description: 'Trick users into downloading malicious payloads', icon: <Skull className="w-4 h-4" /> },
  { value: 'callback_phishing', label: 'Callback Phishing', description: 'Convince targets to call a fake support number', icon: <Mail className="w-4 h-4" /> },
  { value: 'business_email_compromise', label: 'BEC', description: 'Impersonate executives for wire transfer/data theft', icon: <Shield className="w-4 h-4" /> },
  { value: 'mfa_fatigue', label: 'MFA Fatigue', description: 'Overwhelm targets with MFA push notifications', icon: <Zap className="w-4 h-4" /> },
];

const SOPHISTICATION_LEVELS: { value: Sophistication; label: string; color: string }[] = [
  { value: 'basic', label: 'Basic', color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  { value: 'intermediate', label: 'Intermediate', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  { value: 'advanced', label: 'Advanced', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
];

export default function TemplateGenerator() {
  const [step, setStep] = useState<'select' | 'configure' | 'results'>('select');
  const [selectedActor, setSelectedActor] = useState<string | null>(null);
  const [phishingType, setPhishingType] = useState<PhishingType>('credential_harvest');
  const [sophistication, setSophistication] = useState<Sophistication>('intermediate');
  const [targetOrg, setTargetOrg] = useState('');
  const [targetSector, setTargetSector] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [generatedResult, setGeneratedResult] = useState<any>(null);
  const [previewTab, setPreviewTab] = useState('email');

  const generateMutation = trpc.templateGenerator.generateFromThreatActor.useMutation({
    onSuccess: (data) => {
      setGeneratedResult(data);
      setStep('results');
      toast.success("Template generated from threat intelligence.");
    },
    onError: (err) => {
      toast.error(`Generation failed: ${sanitizeErrorForToast(err)}`);
    },
  });

  const deployMutation = trpc.templateGenerator.deployToGophish.useMutation({
    onSuccess: (data) => {
      if (data.errors.length === 0) {
        toast.success("Template and landing page deployed to phishing platform.");
      } else {
        toast.error(`Partial deployment: ${data.errors.join('; ')}`);
      }
    },
    onError: (err) => {
      toast.error(`Deployment failed: ${sanitizeErrorForToast(err)}`);
    },
  });

  // Combine APT scenarios with ransomware IOC data
  const allActors = useMemo(() => {
    return APT_SCENARIOS.map(apt => {
      const ransomwareData = RANSOMWARE_PROFILES.find((r: RansomwareAbilityProfile) => r.groupId === apt.id);
      return {
        ...apt,
        iocs: ransomwareData?.iocs || [],
        abilities: ransomwareData?.abilities || [],
      };
    });
  }, []);

  const filteredActors = useMemo(() => {
    if (!searchQuery) return allActors;
    const q = searchQuery.toLowerCase();
    return allActors.filter(a =>
      a.name.toLowerCase().includes(q) ||
      a.alias.toLowerCase().includes(q) ||
      a.type.toLowerCase().includes(q) ||
      a.targetSectors.some(s => s.toLowerCase().includes(q))
    );
  }, [allActors, searchQuery]);

  const selectedActorData = useMemo(() => {
    return allActors.find(a => a.id === selectedActor);
  }, [allActors, selectedActor]);

  const handleGenerate = () => {
    if (!selectedActorData) return;
    generateMutation.mutate({
      threatActorId: selectedActorData.id,
      threatActorName: selectedActorData.name,
      targetOrg: targetOrg || undefined,
      targetSector: targetSector || selectedActorData.targetSectors[0] || undefined,
      phishingType,
      sophistication,
      iocs: selectedActorData.iocs.slice(0, 10).map((ioc: RansomwareIOC) => ({
        type: ioc.type,
        value: ioc.value,
        description: ioc.description,
      })),
      techniques: selectedActorData.techniques.slice(0, 8).map(t => ({
        id: t.id,
        name: t.name,
        tactic: t.tactic,
      })),
    });
  };

  const handleDeploy = () => {
    if (!generatedResult?.emailTemplate) return;
    deployMutation.mutate({
      template: {
        name: generatedResult.emailTemplate.name,
        subject: generatedResult.emailTemplate.subject,
        html: generatedResult.emailTemplate.html,
        text: generatedResult.emailTemplate.text,
      },
      landingPage: generatedResult.landingPage ? {
        name: generatedResult.landingPage.name,
        html: generatedResult.landingPage.html,
        capture_credentials: true,
        capture_passwords: true,
        redirect_url: generatedResult.landingPage.redirectUrl,
      } : undefined,
    });
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard.`);
  };

  const threatLevelColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'HIGH': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'MEDIUM': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'LOW': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30';
    }
  };

  return (
    <AppShell>
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Sparkles className="w-6 h-6 text-amber-400" />
            IOC-Driven Template Generator
          </h1>
          <p className="text-muted-foreground mt-1">
            Generate realistic phishing templates from real threat actor IOCs and TTPs
          </p>
        </div>
        {step !== 'select' && (
          <Button variant="outline" onClick={() => { setStep('select'); setGeneratedResult(null); }}>
            Start Over
          </Button>
        )}
      </div>

      {/* Progress Steps */}
      <div className="flex items-center gap-2 text-sm">
        <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full ${step === 'select' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'text-muted-foreground'}`}>
          <Target className="w-3.5 h-3.5" /> 1. Select Threat Actor
        </div>
        <ChevronRight className="w-4 h-4 text-muted-foreground" />
        <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full ${step === 'configure' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'text-muted-foreground'}`}>
          <Zap className="w-3.5 h-3.5" /> 2. Configure Template
        </div>
        <ChevronRight className="w-4 h-4 text-muted-foreground" />
        <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full ${step === 'results' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'text-muted-foreground'}`}>
          <Mail className="w-3.5 h-3.5" /> 3. Review & Deploy
        </div>
      </div>

      {/* Step 1: Select Threat Actor */}
      {step === 'select' && (
        <div className="space-y-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search threat actors by name, alias, type, or target sector..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {filteredActors.map(actor => (
              <Card
                key={actor.id}
                className={`cursor-pointer transition-all hover:border-amber-500/50 ${selectedActor === actor.id ? 'border-amber-500 bg-amber-500/5' : ''}`}
                onClick={() => setSelectedActor(actor.id)}
              >
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-semibold">{actor.name}</CardTitle>
                    <Badge variant="outline" className={threatLevelColor(actor.threatLevel)}>
                      {actor.threatLevel}
                    </Badge>
                  </div>
                  <CardDescription className="text-xs">{actor.alias}</CardDescription>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="flex flex-wrap gap-1 mb-2">
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                      {actor.type}
                    </Badge>
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                      {actor.origin}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                    <span>{actor.techniques.length} TTPs</span>
                    <span>{actor.iocs.length} IOCs</span>
                    <span>{actor.abilities.length} Abilities</span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {selectedActor && (
            <div className="flex justify-end">
              <Button onClick={() => setStep('configure')} className="bg-amber-600 hover:bg-amber-700">
                Configure Template <ChevronRight className="w-4 h-4 ml-1" />
              </Button>
            </div>
          )}
        </div>
      )}

      {/* Step 2: Configure Template */}
      {step === 'configure' && selectedActorData && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Actor Intel Summary */}
          <Card className="lg:col-span-1">
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Skull className="w-4 h-4 text-red-400" />
                {selectedActorData.name}
              </CardTitle>
              <CardDescription>{selectedActorData.alias}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label className="text-xs text-muted-foreground">Threat Level</Label>
                <Badge variant="outline" className={`mt-1 ${threatLevelColor(selectedActorData.threatLevel)}`}>
                  {selectedActorData.threatLevel}
                </Badge>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Type</Label>
                <p className="text-sm">{selectedActorData.type}</p>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Target Sectors</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedActorData.targetSectors.map(s => (
                    <Badge key={s} variant="outline" className="text-[10px]">{s}</Badge>
                  ))}
                </div>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Key TTPs ({selectedActorData.techniques.length})</Label>
                <div className="mt-1 space-y-1 max-h-32 overflow-y-auto">
                  {selectedActorData.techniques.slice(0, 6).map(t => (
                    <div key={t.id} className="text-[10px] flex items-center gap-1">
                      <code className="text-amber-400">{t.id}</code>
                      <span className="text-muted-foreground truncate">{t.name}</span>
                    </div>
                  ))}
                  {selectedActorData.techniques.length > 6 && (
                    <p className="text-[10px] text-muted-foreground">+{selectedActorData.techniques.length - 6} more</p>
                  )}
                </div>
              </div>
              {selectedActorData.iocs.length > 0 && (
                <div>
                  <Label className="text-xs text-muted-foreground">IOCs ({selectedActorData.iocs.length})</Label>
                  <div className="mt-1 space-y-1 max-h-32 overflow-y-auto">
                    {selectedActorData.iocs.slice(0, 5).map((ioc: RansomwareIOC, i: number) => (
                      <div key={i} className="text-[10px] flex items-center gap-1">
                        <Badge variant="outline" className="text-[8px] px-1 py-0">{ioc.type}</Badge>
                        <span className="text-muted-foreground truncate">{ioc.value}</span>
                      </div>
                    ))}
                    {selectedActorData.iocs.length > 5 && (
                      <p className="text-[10px] text-muted-foreground">+{selectedActorData.iocs.length - 5} more</p>
                    )}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Right: Configuration */}
          <div className="lg:col-span-2 space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Phishing Type</CardTitle>
                <CardDescription>Select the type of phishing campaign to simulate</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {PHISHING_TYPES.map(pt => (
                    <div
                      key={pt.value}
                      className={`p-3 rounded-lg border cursor-pointer transition-all ${phishingType === pt.value ? 'border-amber-500 bg-amber-500/10' : 'border-border hover:border-amber-500/30'}`}
                      onClick={() => setPhishingType(pt.value)}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        {pt.icon}
                        <span className="text-xs font-medium">{pt.label}</span>
                      </div>
                      <p className="text-[10px] text-muted-foreground">{pt.description}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Sophistication Level</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex gap-2">
                  {SOPHISTICATION_LEVELS.map(sl => (
                    <Badge
                      key={sl.value}
                      variant="outline"
                      className={`cursor-pointer px-4 py-1.5 ${sophistication === sl.value ? sl.color : 'text-muted-foreground hover:text-foreground'}`}
                      onClick={() => setSophistication(sl.value)}
                    >
                      {sl.label}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Target Details (Optional)</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <Label className="text-xs">Target Organization</Label>
                  <Input
                    placeholder="e.g., Acme Corp"
                    value={targetOrg}
                    onChange={(e) => setTargetOrg(e.target.value)}
                    className="mt-1"
                  />
                </div>
                <div>
                  <Label className="text-xs">Target Sector</Label>
                  <Input
                    placeholder={selectedActorData.targetSectors[0] || "e.g., Healthcare"}
                    value={targetSector}
                    onChange={(e) => setTargetSector(e.target.value)}
                    className="mt-1"
                  />
                </div>
              </CardContent>
            </Card>

            <div className="flex justify-between">
              <Button variant="outline" onClick={() => setStep('select')}>
                Back
              </Button>
              <Button
                onClick={handleGenerate}
                disabled={generateMutation.isPending}
                className="bg-amber-600 hover:bg-amber-700"
              >
                {generateMutation.isPending ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Generating from IOCs...
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4 mr-2" />
                    Generate Template
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Step 3: Results */}
      {step === 'results' && generatedResult && (
        <div className="space-y-4">
          {/* Action Bar */}
          <Card>
            <CardContent className="py-3 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="w-5 h-5 text-green-400" />
                <div>
                  <p className="text-sm font-medium">Template Generated Successfully</p>
                  <p className="text-xs text-muted-foreground">
                    Based on {selectedActorData?.name} IOCs and TTPs
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => copyToClipboard(JSON.stringify(generatedResult, null, 2), 'Full template JSON')}
                >
                  <Copy className="w-3.5 h-3.5 mr-1" /> Copy JSON
                </Button>
                <Button
                  size="sm"
                  onClick={handleDeploy}
                  disabled={deployMutation.isPending}
                  className="bg-green-600 hover:bg-green-700"
                >
                  {deployMutation.isPending ? (
                    <><Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" /> Deploying...</>
                  ) : (
                    <><Send className="w-3.5 h-3.5 mr-1" /> Deploy to the phishing platform</>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>

          <Tabs value={previewTab} onValueChange={setPreviewTab}>
            <TabsList>
              <TabsTrigger value="email"><Mail className="w-3.5 h-3.5 mr-1" /> Email Template</TabsTrigger>
              <TabsTrigger value="landing"><Globe className="w-3.5 h-3.5 mr-1" /> Landing Page</TabsTrigger>
              <TabsTrigger value="indicators"><AlertTriangle className="w-3.5 h-3.5 mr-1" /> Indicators</TabsTrigger>
              <TabsTrigger value="training"><FileText className="w-3.5 h-3.5 mr-1" /> Training Notes</TabsTrigger>
            </TabsList>

            <TabsContent value="email" className="space-y-4">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Email Preview */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Eye className="w-4 h-4" /> Email Preview
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="border rounded-lg p-4 bg-white text-black space-y-3">
                      <div className="border-b pb-2 space-y-1">
                        <div className="text-xs text-gray-500">
                          From: <span className="font-medium text-black">{generatedResult.emailTemplate?.senderName}</span>
                          &lt;noreply@{generatedResult.emailTemplate?.senderDomain}&gt;
                        </div>
                        <div className="text-xs text-gray-500">
                          Subject: <span className="font-medium text-black">{generatedResult.emailTemplate?.subject}</span>
                        </div>
                      </div>
                      <div
                        className="text-sm prose prose-sm max-w-none"
                        dangerouslySetInnerHTML={{ __html: generatedResult.emailTemplate?.html || '' }}
                      />
                    </div>
                  </CardContent>
                </Card>

                {/* Email Source */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Code className="w-4 h-4" /> HTML Source
                      </CardTitle>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(generatedResult.emailTemplate?.html || '', 'Email HTML')}
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <pre className="text-[10px] bg-zinc-900 p-3 rounded-lg overflow-auto max-h-96 text-green-400">
                      {generatedResult.emailTemplate?.html}
                    </pre>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Template Details</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <Label className="text-xs text-muted-foreground">Name</Label>
                      <p className="font-medium">{generatedResult.emailTemplate?.name}</p>
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">Sender Name</Label>
                      <p className="font-medium">{generatedResult.emailTemplate?.senderName}</p>
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">Sender Domain</Label>
                      <p className="font-medium">{generatedResult.emailTemplate?.senderDomain}</p>
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">Social Engineering Angle</Label>
                      <p className="font-medium">{generatedResult.emailTemplate?.pretext}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="landing" className="space-y-4">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Eye className="w-4 h-4" /> Landing Page Preview
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="border rounded-lg overflow-hidden bg-white">
                      <iframe
                        srcDoc={generatedResult.landingPage?.html || '<p>No landing page generated</p>'}
                        className="w-full h-96 border-0"
                        sandbox="allow-same-origin"
                        title="Landing page preview"
                      />
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Code className="w-4 h-4" /> HTML Source
                      </CardTitle>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(generatedResult.landingPage?.html || '', 'Landing page HTML')}
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <pre className="text-[10px] bg-zinc-900 p-3 rounded-lg overflow-auto max-h-96 text-green-400">
                      {generatedResult.landingPage?.html}
                    </pre>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="indicators">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-yellow-400" />
                    Phishing Indicators (for training)
                  </CardTitle>
                  <CardDescription>
                    Red flags that security-aware users should be able to spot
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label className="text-xs text-muted-foreground mb-2 block">Subject Line Keywords</Label>
                    <div className="flex flex-wrap gap-1">
                      {generatedResult.indicators?.subjectKeywords?.map((kw: string, i: number) => (
                        <Badge key={i} variant="outline" className="bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
                          {kw}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground mb-2 block">Body Red Flags</Label>
                    <div className="space-y-1">
                      {generatedResult.indicators?.bodyRedFlags?.map((flag: string, i: number) => (
                        <div key={i} className="flex items-start gap-2 text-sm">
                          <XCircle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />
                          <span>{flag}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground mb-2 block">Technical Indicators</Label>
                    <div className="space-y-1">
                      {generatedResult.indicators?.technicalIndicators?.map((ind: string, i: number) => (
                        <div key={i} className="flex items-start gap-2 text-sm">
                          <Shield className="w-3.5 h-3.5 text-blue-400 mt-0.5 shrink-0" />
                          <span>{ind}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="training">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <FileText className="w-4 h-4 text-blue-400" />
                    Security Awareness Training Notes
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="prose prose-sm prose-invert max-w-none">
                    <p className="whitespace-pre-wrap">{generatedResult.trainingNotes}</p>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      )}
    </div>
    </AppShell>
  );
}
