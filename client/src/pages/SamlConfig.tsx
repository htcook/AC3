import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Shield, Plus, Settings, Trash2, TestTube, Copy, ExternalLink,
  CheckCircle2, XCircle, AlertTriangle, Globe, Key, FileText,
  Building2, Cloud
} from "lucide-react";
import AppShell from "@/components/AppShell";

const PROVIDER_ICONS: Record<string, React.ReactNode> = {
  okta: <img src="https://www.okta.com/sites/default/files/Okta_Logo_BrightBlue_Medium.png" alt="Okta" className="h-5 w-auto" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />,
  azure_ad: <Cloud className="h-5 w-5 text-blue-500" />,
  ping_federate: <Shield className="h-5 w-5 text-green-500" />,
  google_workspace: <Globe className="h-5 w-5 text-red-500" />,
  onelogin: <Key className="h-5 w-5 text-purple-500" />,
  generic: <Shield className="h-5 w-5 text-zinc-400" />,
};

const PROVIDER_LABELS: Record<string, string> = {
  okta: "Okta",
  azure_ad: "Azure AD (Entra ID)",
  ping_federate: "PingFederate",
  google_workspace: "Google Workspace",
  onelogin: "OneLogin",
  generic: "Generic SAML 2.0",
};

const ROLE_OPTIONS = [
  { value: "operator", label: "Operator" },
  { value: "analyst", label: "Analyst" },
  { value: "team_lead", label: "Team Lead" },
  { value: "executive", label: "Executive" },
  { value: "client", label: "Client" },
  { value: "viewer", label: "Viewer" },
  { value: "user", label: "User" },
  { value: "admin", label: "Admin" },
];

export default function SamlConfig() {
  const { user } = useAuth();
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [editingIdp, setEditingIdp] = useState<number | null>(null);
  const [testResults, setTestResults] = useState<Record<number, any>>({});

  const spInfo = trpc.saml.getSpInfo.useQuery();
  const idps = trpc.saml.listIdps.useQuery();
  const templates = trpc.saml.getProviderTemplates.useQuery();
  const authEvents = trpc.saml.getAuthEvents.useQuery({ limit: 20 });

  const createIdp = trpc.saml.createIdp.useMutation({
    onSuccess: () => {
      toast.success("Identity provider configured successfully.");
      idps.refetch();
      setShowAddDialog(false);
    },
    onError: (err) => toast.error(err.message),
  });

  const updateIdp = trpc.saml.updateIdp.useMutation({
    onSuccess: () => {
      toast.success("IdP configuration saved.");
      idps.refetch();
      setEditingIdp(null);
    },
    onError: (err) => toast.error(err.message),
  });

  const deleteIdp = trpc.saml.deleteIdp.useMutation({
    onSuccess: () => {
      toast.success("Identity provider deleted.");
      idps.refetch();
    },
  });

  const testIdp = trpc.saml.testIdp.useMutation({
    onSuccess: (data, vars) => {
      setTestResults((prev) => ({ ...prev, [vars.id]: data }));
      toast.success(data.ssoUrlReachable && data.certificateValid ? "All checks passed!" : "Some checks failed.");
    },
  });

  if (user?.role !== "admin") {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="max-w-md">
          <CardContent className="pt-6 text-center">
            <Shield className="h-12 w-12 mx-auto mb-4 text-zinc-400" />
            <h3 className="text-lg font-semibold">Admin Access Required</h3>
            <p className="text-sm text-muted-foreground mt-2">SAML configuration requires administrator privileges.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <AppShell activePath="/saml-config">
    <div className="space-y-6 p-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6 text-amber-500" />
            SAML 2.0 SSO Configuration
          </h1>
          <p className="text-muted-foreground mt-1">
            Configure enterprise identity providers for phishing-resistant single sign-on.
          </p>
        </div>
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogTrigger asChild>
            <Button><Plus className="h-4 w-4 mr-2" /> Add Identity Provider</Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
            <AddIdPForm
              templates={templates.data}
              onSubmit={(data) => createIdp.mutate(data)}
              isLoading={createIdp.isPending}
            />
          </DialogContent>
        </Dialog>
      </div>

      <Tabs defaultValue="providers" className="space-y-4">
        <TabsList>
          <TabsTrigger value="providers">Identity Providers</TabsTrigger>
          <TabsTrigger value="sp-info">SP Metadata</TabsTrigger>
          <TabsTrigger value="events">Auth Events</TabsTrigger>
        </TabsList>

        {/* Identity Providers Tab */}
        <TabsContent value="providers" className="space-y-4">
          {idps.data?.length === 0 && (
            <Card className="border-dashed">
              <CardContent className="pt-6 text-center">
                <Building2 className="h-12 w-12 mx-auto mb-4 text-zinc-400" />
                <h3 className="text-lg font-semibold">No Identity Providers Configured</h3>
                <p className="text-sm text-muted-foreground mt-2 mb-4">
                  Add an enterprise IdP (Okta, Azure AD, PingFederate) to enable SAML SSO.
                </p>
                <Button onClick={() => setShowAddDialog(true)}>
                  <Plus className="h-4 w-4 mr-2" /> Add Your First IdP
                </Button>
              </CardContent>
            </Card>
          )}

          {idps.data?.map((idp) => (
            <Card key={idp.id} className={!idp.isActive ? "opacity-60" : ""}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {PROVIDER_ICONS[idp.providerType] || PROVIDER_ICONS.generic}
                    <div>
                      <CardTitle className="text-lg">{idp.name}</CardTitle>
                      <CardDescription className="font-mono text-xs mt-0.5">{idp.entityId}</CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={idp.isActive ? "default" : "secondary"}>
                      {idp.isActive ? "Active" : "Disabled"}
                    </Badge>
                    <Badge variant="outline">{PROVIDER_LABELS[idp.providerType]}</Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm mb-4">
                  <div>
                    <span className="text-muted-foreground">SSO URL</span>
                    <p className="font-mono text-xs truncate">{idp.ssoUrl}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Default Role</span>
                    <p className="capitalize">{idp.defaultRole.replace("_", " ")}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">JIT Provisioning</span>
                    <p>{idp.jitProvisioning ? "Enabled" : "Disabled"}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Force AuthN</span>
                    <p>{idp.forceAuthn ? "Yes" : "No"}</p>
                  </div>
                </div>

                {/* Test Results */}
                {testResults[idp.id] && (
                  <div className="bg-zinc-900/50 rounded-lg p-3 mb-4 grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                    <div className="flex items-center gap-2">
                      {testResults[idp.id].ssoUrlReachable ? <CheckCircle2 className="h-4 w-4 text-green-500" /> : <XCircle className="h-4 w-4 text-red-500" />}
                      SSO URL Reachable
                    </div>
                    <div className="flex items-center gap-2">
                      {testResults[idp.id].certificateValid ? <CheckCircle2 className="h-4 w-4 text-green-500" /> : <XCircle className="h-4 w-4 text-red-500" />}
                      Certificate Valid
                    </div>
                    <div className="flex items-center gap-2">
                      {testResults[idp.id].certificateExpiry ? (
                        <span className="text-muted-foreground">Expires: {new Date(testResults[idp.id].certificateExpiry).toLocaleDateString()}</span>
                      ) : (
                        <span className="text-muted-foreground">No expiry info</span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {testResults[idp.id].metadataValid ? <CheckCircle2 className="h-4 w-4 text-green-500" /> : <AlertTriangle className="h-4 w-4 text-yellow-500" />}
                      Metadata {testResults[idp.id].metadataValid ? "Present" : "Missing"}
                    </div>
                  </div>
                )}

                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" onClick={() => testIdp.mutate({ id: idp.id })} disabled={testIdp.isPending}>
                    <TestTube className="h-3.5 w-3.5 mr-1" /> Test Connection
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => {
                    updateIdp.mutate({ id: idp.id, isActive: !idp.isActive });
                  }}>
                    {idp.isActive ? "Disable" : "Enable"}
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setEditingIdp(idp.id)}>
                    <Settings className="h-3.5 w-3.5 mr-1" /> Edit
                  </Button>
                  <Button variant="ghost" size="sm" className="text-red-500 hover:text-red-400" onClick={() => {
                    if (confirm(`Delete IdP "${idp.name}"? This cannot be undone.`)) {
                      deleteIdp.mutate({ id: idp.id });
                    }
                  }}>
                    <Trash2 className="h-3.5 w-3.5 mr-1" /> Delete
                  </Button>
                  {idp.isActive && (
                    <Button variant="outline" size="sm" className="ml-auto" onClick={() => {
                      window.open(`/api/saml/login/${idp.id}`, "_blank");
                    }}>
                      <ExternalLink className="h-3.5 w-3.5 mr-1" /> Test SSO Login
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        {/* SP Metadata Tab */}
        <TabsContent value="sp-info" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" /> Service Provider Metadata
              </CardTitle>
              <CardDescription>
                Use these values when configuring Caldera Dashboard as a SAML SP in your IdP.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {spInfo.data && (
                <>
                  <MetadataField label="Entity ID (Audience URI)" value={spInfo.data.entityId} />
                  <MetadataField label="ACS URL (Reply URL)" value={spInfo.data.acsUrl} />
                  <MetadataField label="Metadata URL" value={spInfo.data.metadataUrl} isLink />
                  <div>
                    <Label className="text-muted-foreground text-xs">Supported NameID Formats</Label>
                    <div className="flex flex-wrap gap-2 mt-1">
                      {spInfo.data.nameIdFormats.map((fmt) => (
                        <Badge key={fmt} variant="outline" className="font-mono text-xs">{fmt.split(":").pop()}</Badge>
                      ))}
                    </div>
                  </div>
                  <div>
                    <Label className="text-muted-foreground text-xs">Supported Bindings</Label>
                    <div className="flex gap-2 mt-1">
                      {spInfo.data.supportedBindings.map((b) => (
                        <Badge key={b} variant="outline">{b}</Badge>
                      ))}
                    </div>
                  </div>
                  <div className="pt-2">
                    <Button variant="outline" onClick={() => window.open(spInfo.data!.metadataUrl, "_blank")}>
                      <FileText className="h-4 w-4 mr-2" /> Download SP Metadata XML
                    </Button>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {/* Quick Setup Guides */}
          <Card>
            <CardHeader>
              <CardTitle>Quick Setup Guides</CardTitle>
              <CardDescription>Step-by-step instructions for popular identity providers.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { provider: "Okta", url: "https://developer.okta.com/docs/guides/build-sso-integration/saml2/main/", color: "text-blue-400" },
                  { provider: "Azure AD", url: "https://learn.microsoft.com/en-us/entra/identity/saas-apps/tutorial-list", color: "text-blue-500" },
                  { provider: "PingFederate", url: "https://docs.pingidentity.com/pingfederate/latest/administrators_reference_guide/pf_sp_connections.html", color: "text-green-500" },
                ].map((guide) => (
                  <a key={guide.provider} href={guide.url} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-3 p-3 rounded-lg border border-border/50 hover:border-border transition-colors">
                    <ExternalLink className={`h-4 w-4 ${guide.color}`} />
                    <span className="text-sm font-medium">{guide.provider} Setup Guide</span>
                  </a>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Auth Events Tab */}
        <TabsContent value="events" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>SAML Authentication Events</CardTitle>
              <CardDescription>Recent SAML authentication activity across all IdPs.</CardDescription>
            </CardHeader>
            <CardContent>
              {authEvents.data?.length === 0 ? (
                <p className="text-center text-muted-foreground py-8">No SAML authentication events yet.</p>
              ) : (
                <div className="space-y-2">
                  {authEvents.data?.map((event) => (
                    <div key={event.id} className="flex items-center gap-3 p-3 rounded-lg bg-zinc-900/30 text-sm">
                      {event.eventType === "login_success" && <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />}
                      {event.eventType === "login_failure" && <XCircle className="h-4 w-4 text-red-500 shrink-0" />}
                      {event.eventType === "jit_provision" && <Plus className="h-4 w-4 text-blue-500 shrink-0" />}
                      {(event.eventType === "assertion_error" || event.eventType === "signature_invalid") && <AlertTriangle className="h-4 w-4 text-yellow-500 shrink-0" />}
                      {event.eventType === "logout" && <Shield className="h-4 w-4 text-zinc-400 shrink-0" />}
                      <div className="flex-1 min-w-0">
                        <span className="font-medium capitalize">{event.eventType.replace(/_/g, " ")}</span>
                        {event.nameId && <span className="text-muted-foreground ml-2">— {event.nameId}</span>}
                        {event.errorDetails && <p className="text-xs text-red-400 mt-0.5 truncate">{event.errorDetails}</p>}
                      </div>
                      <span className="text-muted-foreground text-xs shrink-0">
                        {event.ipAddress && `${event.ipAddress} · `}
                        {new Date(event.createdAt).toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Edit Dialog */}
      {editingIdp && (
        <EditIdPDialog
          idpId={editingIdp}
          onClose={() => setEditingIdp(null)}
          onSave={(data) => updateIdp.mutate({ id: editingIdp, ...data })}
          isLoading={updateIdp.isPending}
        />
      )}
    </div>
    </AppShell>
  );
}

// ─── Sub-components ─────────────────────────────────────────────────────────

function MetadataField({ label, value, isLink }: { label: string; value: string; isLink?: boolean }) {
  return (
    <div>
      <Label className="text-muted-foreground text-xs">{label}</Label>
      <div className="flex items-center gap-2 mt-1">
        <code className="flex-1 bg-zinc-900/50 px-3 py-2 rounded text-sm font-mono break-all">{value}</code>
        <Button variant="ghost" size="icon" className="shrink-0" onClick={() => {
          navigator.clipboard.writeText(value);
          toast.success(`${label} copied to clipboard.`);
        }}>
          <Copy className="h-4 w-4" />
        </Button>
        {isLink && (
          <Button variant="ghost" size="icon" className="shrink-0" onClick={() => window.open(value, "_blank")}>
            <ExternalLink className="h-4 w-4" />
          </Button>
        )}
      </div>
    </div>
  );
}

function AddIdPForm({ templates, onSubmit, isLoading }: {
  templates?: any;
  onSubmit: (data: any) => void;
  isLoading: boolean;
}) {
  const [provider, setProvider] = useState("generic");
  const [form, setForm] = useState({
    name: "",
    entityId: "",
    ssoUrl: "",
    sloUrl: "",
    certificate: "",
    metadataXml: "",
    defaultRole: "operator" as string,
    jitProvisioning: true,
    forceAuthn: false,
    wantAssertionsSigned: true,
    wantResponseSigned: true,
  });

  const handleProviderChange = (val: string) => {
    setProvider(val);
    if (templates?.[val]) {
      setForm((prev) => ({
        ...prev,
        name: templates[val].label,
      }));
    }
  };

  return (
    <>
      <DialogHeader>
        <DialogTitle>Add Identity Provider</DialogTitle>
        <DialogDescription>Configure a SAML 2.0 IdP for enterprise SSO.</DialogDescription>
      </DialogHeader>
      <div className="space-y-4 py-4">
        <div>
          <Label>Provider Type</Label>
          <Select value={provider} onValueChange={handleProviderChange}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {Object.entries(PROVIDER_LABELS).map(([key, label]) => (
                <SelectItem key={key} value={key}>{label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Display Name *</Label>
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Okta Production" />
        </div>
        <div>
          <Label>Entity ID (IdP Issuer) *</Label>
          <Input value={form.entityId} onChange={(e) => setForm({ ...form, entityId: e.target.value })}
            placeholder={templates?.[provider]?.entityIdHint || "https://idp.example.com/metadata"} />
        </div>
        <div>
          <Label>SSO URL *</Label>
          <Input value={form.ssoUrl} onChange={(e) => setForm({ ...form, ssoUrl: e.target.value })}
            placeholder={templates?.[provider]?.ssoUrlHint || "https://idp.example.com/sso"} />
        </div>
        <div>
          <Label>SLO URL (optional)</Label>
          <Input value={form.sloUrl} onChange={(e) => setForm({ ...form, sloUrl: e.target.value })} placeholder="https://idp.example.com/slo" />
        </div>
        <div>
          <Label>X.509 Certificate (PEM) *</Label>
          <Textarea value={form.certificate} onChange={(e) => setForm({ ...form, certificate: e.target.value })}
            placeholder="-----BEGIN CERTIFICATE-----&#10;MIIDp...&#10;-----END CERTIFICATE-----"
            className="font-mono text-xs" rows={6} />
        </div>
        <div>
          <Label>IdP Metadata XML (optional)</Label>
          <Textarea value={form.metadataXml} onChange={(e) => setForm({ ...form, metadataXml: e.target.value })}
            placeholder="Paste full IdP metadata XML here..." className="font-mono text-xs" rows={4} />
        </div>
        <div>
          <Label>Default Role for New Users</Label>
          <Select value={form.defaultRole} onValueChange={(v) => setForm({ ...form, defaultRole: v })}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {ROLE_OPTIONS.map((r) => (
                <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label>Just-In-Time User Provisioning</Label>
            <Switch checked={form.jitProvisioning} onCheckedChange={(v) => setForm({ ...form, jitProvisioning: v })} />
          </div>
          <div className="flex items-center justify-between">
            <Label>Force Re-Authentication</Label>
            <Switch checked={form.forceAuthn} onCheckedChange={(v) => setForm({ ...form, forceAuthn: v })} />
          </div>
          <div className="flex items-center justify-between">
            <Label>Require Signed Assertions</Label>
            <Switch checked={form.wantAssertionsSigned} onCheckedChange={(v) => setForm({ ...form, wantAssertionsSigned: v })} />
          </div>
          <div className="flex items-center justify-between">
            <Label>Require Signed Responses</Label>
            <Switch checked={form.wantResponseSigned} onCheckedChange={(v) => setForm({ ...form, wantResponseSigned: v })} />
          </div>
        </div>
      </div>
      <DialogFooter>
        <Button onClick={() => onSubmit({ ...form, providerType: provider })} disabled={isLoading || !form.name || !form.entityId || !form.ssoUrl || !form.certificate}>
          {isLoading ? "Creating..." : "Create Identity Provider"}
        </Button>
      </DialogFooter>
    </>
  );
}

function EditIdPDialog({ idpId, onClose, onSave, isLoading }: {
  idpId: number;
  onClose: () => void;
  onSave: (data: any) => void;
  isLoading: boolean;
}) {
  const idp = trpc.saml.getIdp.useQuery({ id: idpId });
  const [form, setForm] = useState<any>(null);

  // Initialize form when data loads
  if (idp.data && !form) {
    setForm({
      name: idp.data.name,
      ssoUrl: idp.data.ssoUrl,
      sloUrl: idp.data.sloUrl || "",
      certificate: idp.data.certificate,
      defaultRole: idp.data.defaultRole,
      jitProvisioning: idp.data.jitProvisioning,
      forceAuthn: idp.data.forceAuthn,
      wantAssertionsSigned: idp.data.wantAssertionsSigned,
      wantResponseSigned: idp.data.wantResponseSigned,
    });
  }

  return (
      <Dialog open onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Edit Identity Provider</DialogTitle>
          <DialogDescription>Update the SAML IdP configuration.</DialogDescription>
        </DialogHeader>
        {form && (
          <div className="space-y-4 py-4">
            <div>
              <Label>Display Name</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>
            <div>
              <Label>SSO URL</Label>
              <Input value={form.ssoUrl} onChange={(e) => setForm({ ...form, ssoUrl: e.target.value })} />
            </div>
            <div>
              <Label>SLO URL</Label>
              <Input value={form.sloUrl} onChange={(e) => setForm({ ...form, sloUrl: e.target.value })} />
            </div>
            <div>
              <Label>X.509 Certificate (PEM)</Label>
              <Textarea value={form.certificate} onChange={(e) => setForm({ ...form, certificate: e.target.value })}
                className="font-mono text-xs" rows={6} />
            </div>
            <div>
              <Label>Default Role</Label>
              <Select value={form.defaultRole} onValueChange={(v) => setForm({ ...form, defaultRole: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ROLE_OPTIONS.map((r) => (
                    <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label>JIT Provisioning</Label>
                <Switch checked={form.jitProvisioning} onCheckedChange={(v) => setForm({ ...form, jitProvisioning: v })} />
              </div>
              <div className="flex items-center justify-between">
                <Label>Force Re-Authentication</Label>
                <Switch checked={form.forceAuthn} onCheckedChange={(v) => setForm({ ...form, forceAuthn: v })} />
              </div>
              <div className="flex items-center justify-between">
                <Label>Require Signed Assertions</Label>
                <Switch checked={form.wantAssertionsSigned} onCheckedChange={(v) => setForm({ ...form, wantAssertionsSigned: v })} />
              </div>
              <div className="flex items-center justify-between">
                <Label>Require Signed Responses</Label>
                <Switch checked={form.wantResponseSigned} onCheckedChange={(v) => setForm({ ...form, wantResponseSigned: v })} />
              </div>
            </div>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => onSave(form)} disabled={isLoading}>
            {isLoading ? "Saving..." : "Save Changes"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
