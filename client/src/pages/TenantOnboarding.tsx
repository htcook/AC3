import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { useLocation } from "wouter";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import {
  Building2, Shield, Users, Rocket, Check, ChevronRight, ChevronLeft,
  Globe, Lock, UserPlus, Plus, X, AlertTriangle, CheckCircle2, Loader2
} from "lucide-react";
import AppShell from "@/components/AppShell";

const STEPS = [
  { id: "org_info", label: "Organization", icon: Building2, description: "Set up your organization profile" },
  { id: "idp_config", label: "Authentication", icon: Shield, description: "Configure identity provider" },
  { id: "team_invites", label: "Team", icon: Users, description: "Invite your team members" },
  { id: "review_launch", label: "Launch", icon: Rocket, description: "Review and activate" },
] as const;

type StepId = typeof STEPS[number]["id"];

export default function TenantOnboarding() {
  const { user } = useAuth();
  const [, navigate] = useLocation();
  const [currentStep, setCurrentStep] = useState<StepId>("org_info");
  const [tenantId, setTenantId] = useState<number | null>(null);

  // Form state for each step
  const [orgInfo, setOrgInfo] = useState({
    orgName: "", orgDomain: "", industry: "" as string,
    orgSize: "" as string, complianceFrameworks: [] as string[],
    primaryContact: { name: user?.name || "", email: "", phone: "", title: "" },
  });

  const [idpConfig, setIdpConfig] = useState({
    authMethod: "platform_only" as "saml" | "oauth" | "platform_only",
    saml: { entityId: "", ssoUrl: "", certificate: "", provider: "custom" as string, signatureAlgorithm: "sha256" as string },
    mfaRequired: true, sessionTimeout: 28800,
  });

  const [invites, setInvites] = useState<Array<{ email: string; role: string; department: string }>>([]);
  const [newInvite, setNewInvite] = useState({ email: "", role: "operator", department: "" });

  // Check existing session
  const sessionQuery = trpc.tenantOnboarding.getSession.useQuery();
  const industriesQuery = trpc.tenantOnboarding.getIndustries.useQuery();
  const frameworksQuery = trpc.tenantOnboarding.getComplianceFrameworks.useQuery();

  // Mutations
  const saveOrgMut = trpc.tenantOnboarding.saveOrgInfo.useMutation({
    onSuccess: (data) => {
      setTenantId(data.tenantId);
      setCurrentStep("idp_config");
      toast.success(data.message);
    },
    onError: (err) => toast.error(err.message),
  });

  const saveIdpMut = trpc.tenantOnboarding.saveIdpConfig.useMutation({
    onSuccess: (data) => {
      setCurrentStep("team_invites");
      toast.success(data.message);
    },
    onError: (err) => toast.error(err.message),
  });

  const testIdpMut = trpc.tenantOnboarding.testIdpConnection.useMutation({
    onSuccess: (data) => {
      if (data.success) toast.success("IdP connection test passed");
      else toast.error("IdP connection test failed — check configuration");
    },
  });

  const saveInvitesMut = trpc.tenantOnboarding.saveTeamInvites.useMutation({
    onSuccess: (data) => {
      setCurrentStep("review_launch");
      toast.success(`${data.summary.sent} invitation(s) created`);
    },
    onError: (err) => toast.error(err.message),
  });

  const activateMut = trpc.tenantOnboarding.activateTenant.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      navigate(data.redirectTo || "/dashboard");
    },
    onError: (err) => toast.error(err.message),
  });

  const reviewQuery = trpc.tenantOnboarding.getReviewSummary.useQuery(
    { tenantId: tenantId! },
    { enabled: currentStep === "review_launch" && !!tenantId }
  );

  // If user already has a tenant, redirect
  if (sessionQuery.data?.hasExistingTenant) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-6">
        <Card className="max-w-md w-full">
          <CardHeader className="text-center">
            <CheckCircle2 className="w-12 h-12 text-green-500 mx-auto mb-2" />
            <CardTitle>Already Onboarded</CardTitle>
            <CardDescription>
              Your organization "{sessionQuery.data.tenantName}" is already set up.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            <Button onClick={() => navigate("/dashboard")}>Go to Dashboard</Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const currentStepIndex = STEPS.findIndex(s => s.id === currentStep);

  const addInvite = () => {
    if (!newInvite.email) return;
    if (invites.some(i => i.email === newInvite.email)) {
      toast.error("Email already added");
      return;
    }
    setInvites([...invites, { ...newInvite }]);
    setNewInvite({ email: "", role: "operator", department: "" });
  };

  const removeInvite = (email: string) => {
    setInvites(invites.filter(i => i.email !== email));
  };

  const handleNext = () => {
    switch (currentStep) {
      case "org_info":
        if (!orgInfo.orgName || !orgInfo.orgDomain || !orgInfo.industry || !orgInfo.orgSize) {
          toast.error("Please fill in all required fields");
          return;
        }
        saveOrgMut.mutate({
          orgName: orgInfo.orgName,
          orgDomain: orgInfo.orgDomain,
          industry: orgInfo.industry as any,
          orgSize: orgInfo.orgSize as any,
          complianceFrameworks: orgInfo.complianceFrameworks as any[],
          primaryContact: orgInfo.primaryContact,
        });
        break;
      case "idp_config":
        if (!tenantId) return;
        saveIdpMut.mutate({ tenantId, config: idpConfig as any });
        break;
      case "team_invites":
        if (!tenantId) return;
        saveInvitesMut.mutate({
          tenantId,
          invites: invites.map(i => ({
            email: i.email,
            role: i.role as any,
            department: i.department || undefined,
            sendImmediately: true,
          })),
        });
        break;
      case "review_launch":
        if (!tenantId) return;
        activateMut.mutate({ tenantId });
        break;
    }
  };

  const handleBack = () => {
    const prevIndex = currentStepIndex - 1;
    if (prevIndex >= 0) setCurrentStep(STEPS[prevIndex].id);
  };

  const isLoading = saveOrgMut.isPending || saveIdpMut.isPending || saveInvitesMut.isPending || activateMut.isPending;

  return (
      <AppShell activePath="/onboarding">
      <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="border-b bg-card">
        <div className="max-w-4xl mx-auto px-6 py-6">
          <h1 className="text-2xl font-bold text-foreground">Organization Onboarding</h1>
          <p className="text-muted-foreground mt-1">Set up your organization in a few steps</p>
        </div>
      </div>

      {/* Progress Steps */}
      <div className="max-w-4xl mx-auto px-6 py-6">
        <div className="flex items-center justify-between mb-8">
          {STEPS.map((step, idx) => {
            const StepIcon = step.icon;
            const isActive = step.id === currentStep;
            const isComplete = idx < currentStepIndex;
            return (
              <div key={step.id} className="flex items-center flex-1">
                <div className="flex flex-col items-center">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center transition-colors ${
                    isComplete ? "bg-green-500 text-white" :
                    isActive ? "bg-primary text-primary-foreground" :
                    "bg-muted text-muted-foreground"
                  }`}>
                    {isComplete ? <Check className="w-5 h-5" /> : <StepIcon className="w-5 h-5" />}
                  </div>
                  <span className={`text-xs mt-2 font-medium ${isActive ? "text-foreground" : "text-muted-foreground"}`}>
                    {step.label}
                  </span>
                </div>
                {idx < STEPS.length - 1 && (
                  <div className={`flex-1 h-0.5 mx-3 mt-[-1rem] ${isComplete ? "bg-green-500" : "bg-muted"}`} />
                )}
              </div>
            );
          })}
        </div>

        {/* Step Content */}
        <Card>
          <CardHeader>
            <CardTitle>{STEPS[currentStepIndex].label}</CardTitle>
            <CardDescription>{STEPS[currentStepIndex].description}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Step 1: Organization Info */}
            {currentStep === "org_info" && (
              <>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Organization Name *</Label>
                    <Input placeholder="Acme Corporation" value={orgInfo.orgName}
                      onChange={e => setOrgInfo({ ...orgInfo, orgName: e.target.value })} />
                  </div>
                  <div className="space-y-2">
                    <Label>Primary Domain *</Label>
                    <Input placeholder="acme.com" value={orgInfo.orgDomain}
                      onChange={e => setOrgInfo({ ...orgInfo, orgDomain: e.target.value })} />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Industry *</Label>
                    <Select value={orgInfo.industry} onValueChange={v => setOrgInfo({ ...orgInfo, industry: v })}>
                      <SelectTrigger><SelectValue placeholder="Select industry" /></SelectTrigger>
                      <SelectContent>
                        {(industriesQuery.data || []).map(i => (
                          <SelectItem key={i.value} value={i.value}>{i.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Organization Size *</Label>
                    <Select value={orgInfo.orgSize} onValueChange={v => setOrgInfo({ ...orgInfo, orgSize: v })}>
                      <SelectTrigger><SelectValue placeholder="Select size" /></SelectTrigger>
                      <SelectContent>
                        {["1-10","11-50","51-200","201-500","501-1000","1000+"].map(s => (
                          <SelectItem key={s} value={s}>{s} employees</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>Compliance Frameworks</Label>
                  <div className="flex flex-wrap gap-2">
                    {(frameworksQuery.data || []).map(f => (
                      <Badge key={f.value} variant={orgInfo.complianceFrameworks.includes(f.value) ? "default" : "outline"}
                        className="cursor-pointer" title={f.description}
                        onClick={() => {
                          const has = orgInfo.complianceFrameworks.includes(f.value);
                          setOrgInfo({
                            ...orgInfo,
                            complianceFrameworks: has
                              ? orgInfo.complianceFrameworks.filter(c => c !== f.value)
                              : [...orgInfo.complianceFrameworks, f.value],
                          });
                        }}>
                        {f.label}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div className="border-t pt-4">
                  <h3 className="font-semibold mb-3">Primary Contact</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Full Name *</Label>
                      <Input value={orgInfo.primaryContact.name}
                        onChange={e => setOrgInfo({ ...orgInfo, primaryContact: { ...orgInfo.primaryContact, name: e.target.value } })} />
                    </div>
                    <div className="space-y-2">
                      <Label>Email *</Label>
                      <Input type="email" value={orgInfo.primaryContact.email}
                        onChange={e => setOrgInfo({ ...orgInfo, primaryContact: { ...orgInfo.primaryContact, email: e.target.value } })} />
                    </div>
                    <div className="space-y-2">
                      <Label>Phone</Label>
                      <Input value={orgInfo.primaryContact.phone}
                        onChange={e => setOrgInfo({ ...orgInfo, primaryContact: { ...orgInfo.primaryContact, phone: e.target.value } })} />
                    </div>
                    <div className="space-y-2">
                      <Label>Title</Label>
                      <Input value={orgInfo.primaryContact.title}
                        onChange={e => setOrgInfo({ ...orgInfo, primaryContact: { ...orgInfo.primaryContact, title: e.target.value } })} />
                    </div>
                  </div>
                </div>
              </>
            )}

            {/* Step 2: IdP Configuration */}
            {currentStep === "idp_config" && (
              <>
                <div className="space-y-4">
                  <Label>Authentication Method</Label>
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      { value: "saml", label: "SAML 2.0 SSO", desc: "Enterprise SSO (Okta, Azure AD, PingFederate)", icon: Shield },
                      { value: "oauth", label: "OAuth 2.0", desc: "OAuth-based identity provider", icon: Globe },
                      { value: "platform_only", label: "Platform Auth", desc: "Use built-in Manus authentication", icon: Lock },
                    ].map(opt => (
                      <Card key={opt.value}
                        className={`cursor-pointer transition-all ${idpConfig.authMethod === opt.value ? "ring-2 ring-primary" : "hover:bg-accent/50"}`}
                        onClick={() => setIdpConfig({ ...idpConfig, authMethod: opt.value as any })}>
                        <CardContent className="p-4 text-center">
                          <opt.icon className="w-8 h-8 mx-auto mb-2 text-primary" />
                          <p className="font-semibold text-sm">{opt.label}</p>
                          <p className="text-xs text-muted-foreground mt-1">{opt.desc}</p>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </div>

                {idpConfig.authMethod === "saml" && (
                  <div className="space-y-4 border-t pt-4">
                    <h3 className="font-semibold">SAML 2.0 Configuration</h3>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>IdP Provider</Label>
                        <Select value={idpConfig.saml.provider}
                          onValueChange={v => setIdpConfig({ ...idpConfig, saml: { ...idpConfig.saml, provider: v } })}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            {["okta","azure_ad","ping_federate","onelogin","google","custom"].map(p => (
                              <SelectItem key={p} value={p}>{p.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>Signature Algorithm</Label>
                        <Select value={idpConfig.saml.signatureAlgorithm}
                          onValueChange={v => setIdpConfig({ ...idpConfig, saml: { ...idpConfig.saml, signatureAlgorithm: v } })}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="sha256">SHA-256 (FIPS)</SelectItem>
                            <SelectItem value="sha384">SHA-384 (FIPS)</SelectItem>
                            <SelectItem value="sha512">SHA-512 (FIPS)</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>Entity ID (Issuer)</Label>
                      <Input placeholder="https://idp.example.com/metadata" value={idpConfig.saml.entityId}
                        onChange={e => setIdpConfig({ ...idpConfig, saml: { ...idpConfig.saml, entityId: e.target.value } })} />
                    </div>
                    <div className="space-y-2">
                      <Label>SSO URL</Label>
                      <Input placeholder="https://idp.example.com/sso/saml" value={idpConfig.saml.ssoUrl}
                        onChange={e => setIdpConfig({ ...idpConfig, saml: { ...idpConfig.saml, ssoUrl: e.target.value } })} />
                    </div>
                    <div className="space-y-2">
                      <Label>X.509 Certificate</Label>
                      <Textarea rows={4} placeholder="Paste the IdP signing certificate (PEM format)" value={idpConfig.saml.certificate}
                        onChange={e => setIdpConfig({ ...idpConfig, saml: { ...idpConfig.saml, certificate: e.target.value } })} />
                    </div>
                    {tenantId && (
                      <Button variant="outline" size="sm"
                        onClick={() => testIdpMut.mutate({ tenantId, authMethod: "saml" })}
                        disabled={testIdpMut.isPending}>
                        {testIdpMut.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Shield className="w-4 h-4 mr-2" />}
                        Test Connection
                      </Button>
                    )}
                  </div>
                )}

                <div className="border-t pt-4 space-y-4">
                  <h3 className="font-semibold">Security Settings</h3>
                  <div className="flex items-center justify-between">
                    <div>
                      <Label>Require Phishing-Resistant MFA</Label>
                      <p className="text-xs text-muted-foreground">Required for federal compliance (NIST SP 800-63B AAL2+)</p>
                    </div>
                    <Switch checked={idpConfig.mfaRequired}
                      onCheckedChange={v => setIdpConfig({ ...idpConfig, mfaRequired: v })} />
                  </div>
                  <div className="space-y-2">
                    <Label>Session Timeout</Label>
                    <Select value={String(idpConfig.sessionTimeout)}
                      onValueChange={v => setIdpConfig({ ...idpConfig, sessionTimeout: parseInt(v) })}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="3600">1 hour</SelectItem>
                        <SelectItem value="14400">4 hours</SelectItem>
                        <SelectItem value="28800">8 hours (default)</SelectItem>
                        <SelectItem value="43200">12 hours</SelectItem>
                        <SelectItem value="86400">24 hours</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </>
            )}

            {/* Step 3: Team Invitations */}
            {currentStep === "team_invites" && (
              <>
                <div className="space-y-4">
                  <div className="flex gap-3 items-end">
                    <div className="flex-1 space-y-2">
                      <Label>Email Address</Label>
                      <Input type="email" placeholder="colleague@example.com" value={newInvite.email}
                        onChange={e => setNewInvite({ ...newInvite, email: e.target.value })}
                        onKeyDown={e => e.key === "Enter" && addInvite()} />
                    </div>
                    <div className="w-40 space-y-2">
                      <Label>Role</Label>
                      <Select value={newInvite.role} onValueChange={v => setNewInvite({ ...newInvite, role: v })}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {["admin","operator","analyst","team_lead","client","executive"].map(r => (
                            <SelectItem key={r} value={r}>{r.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="w-36 space-y-2">
                      <Label>Department</Label>
                      <Input placeholder="Optional" value={newInvite.department}
                        onChange={e => setNewInvite({ ...newInvite, department: e.target.value })} />
                    </div>
                    <Button onClick={addInvite} size="icon"><Plus className="w-4 h-4" /></Button>
                  </div>

                  {invites.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <UserPlus className="w-10 h-10 mx-auto mb-2 opacity-50" />
                      <p>No team members added yet</p>
                      <p className="text-xs">Add emails above or skip this step</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {invites.map((inv, idx) => (
                        <div key={idx} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                          <div className="flex items-center gap-3">
                            <Users className="w-4 h-4 text-muted-foreground" />
                            <span className="font-medium">{inv.email}</span>
                            <Badge variant="outline">{inv.role.replace(/_/g, " ")}</Badge>
                            {inv.department && <span className="text-xs text-muted-foreground">{inv.department}</span>}
                          </div>
                          <Button variant="ghost" size="icon" onClick={() => removeInvite(inv.email)}>
                            <X className="w-4 h-4" />
                          </Button>
                        </div>
                      ))}
                      <p className="text-xs text-muted-foreground">{invites.length} invitation(s) ready to send</p>
                    </div>
                  )}
                </div>
              </>
            )}

            {/* Step 4: Review & Launch */}
            {currentStep === "review_launch" && reviewQuery.data && (
              <>
                <div className="grid grid-cols-2 gap-4">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Building2 className="w-4 h-4" /> Organization
                        {reviewQuery.data.readiness.orgInfoComplete ? <CheckCircle2 className="w-4 h-4 text-green-500" /> : <AlertTriangle className="w-4 h-4 text-yellow-500" />}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="text-sm space-y-1">
                      <p><strong>{reviewQuery.data.organization.name}</strong></p>
                      <p className="text-muted-foreground">{reviewQuery.data.organization.slug}</p>
                      <p className="text-muted-foreground">{reviewQuery.data.organization.industry.replace(/_/g, " ")}</p>
                      <p className="text-muted-foreground">{reviewQuery.data.organization.orgSize} employees</p>
                      {reviewQuery.data.organization.complianceFrameworks.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {reviewQuery.data.organization.complianceFrameworks.map((f: string) => (
                            <Badge key={f} variant="secondary" className="text-xs">{f.replace(/_/g, " ").toUpperCase()}</Badge>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Shield className="w-4 h-4" /> Authentication
                        {reviewQuery.data.readiness.authConfigured ? <CheckCircle2 className="w-4 h-4 text-green-500" /> : <AlertTriangle className="w-4 h-4 text-yellow-500" />}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="text-sm space-y-1">
                      <p><strong>{reviewQuery.data.authentication.method.replace(/_/g, " ").toUpperCase()}</strong></p>
                      {reviewQuery.data.authentication.idpProvider && (
                        <p className="text-muted-foreground">Provider: {reviewQuery.data.authentication.idpProvider}</p>
                      )}
                      <p className="text-muted-foreground">MFA: {reviewQuery.data.authentication.mfaRequired ? "Required" : "Optional"}</p>
                      <p className="text-muted-foreground">Session: {Math.round(reviewQuery.data.authentication.sessionTimeout / 3600)}h timeout</p>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Users className="w-4 h-4" /> Team
                        {reviewQuery.data.readiness.teamInvited ? <CheckCircle2 className="w-4 h-4 text-green-500" /> : <AlertTriangle className="w-4 h-4 text-yellow-500" />}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="text-sm space-y-1">
                      <p><strong>{reviewQuery.data.team.totalExpected}</strong> total members expected</p>
                      <p className="text-muted-foreground">{reviewQuery.data.team.currentMembers} active, {reviewQuery.data.team.pendingInvites} pending</p>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Rocket className="w-4 h-4" /> Readiness
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="text-sm space-y-2">
                      {Object.entries(reviewQuery.data.readiness).map(([key, val]) => (
                        <div key={key} className="flex items-center gap-2">
                          {val ? <CheckCircle2 className="w-3 h-3 text-green-500" /> : <AlertTriangle className="w-3 h-3 text-yellow-500" />}
                          <span className="text-muted-foreground">{key.replace(/([A-Z])/g, " $1").replace(/^./, s => s.toUpperCase())}</span>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                </div>
              </>
            )}

            {/* Navigation */}
            <div className="flex justify-between pt-4 border-t">
              <Button variant="outline" onClick={handleBack} disabled={currentStepIndex === 0 || isLoading}>
                <ChevronLeft className="w-4 h-4 mr-2" /> Back
              </Button>
              <Button onClick={handleNext} disabled={isLoading}>
                {isLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                {currentStep === "review_launch" ? "Activate Organization" : (
                  currentStep === "team_invites" && invites.length === 0 ? "Skip & Continue" : "Continue"
                )}
                {currentStep !== "review_launch" && <ChevronRight className="w-4 h-4 ml-2" />}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
      </AppShell>
  );
}
