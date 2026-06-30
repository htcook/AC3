import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import {
  Cloud, Key, Shield, Plus, Trash2, CheckCircle, XCircle,
  AlertTriangle, Play, Loader2, RefreshCw, Server
} from "lucide-react";

const PROVIDER_CONFIG = {
  aws: {
    label: "Amazon Web Services",
    color: "text-orange-400",
    bgColor: "bg-orange-500/10",
    credTypes: [
      { value: "aws_access_key", label: "Access Key + Secret Key" },
      { value: "aws_assume_role", label: "Assume Role (Cross-Account)" },
      { value: "aws_session_token", label: "Session Token (Temporary)" },
    ],
    fields: (type: string) => {
      const base = [
        { key: "accessKeyId", label: "Access Key ID", placeholder: "AKIAIOSFODNN7EXAMPLE" },
        { key: "secretAccessKey", label: "Secret Access Key", placeholder: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", type: "password" },
      ];
      if (type === "aws_assume_role") {
        return [...base, { key: "roleArn", label: "Role ARN", placeholder: "arn:aws:iam::123456789012:role/PentestRole" }];
      }
      if (type === "aws_session_token") {
        return [...base, { key: "sessionToken", label: "Session Token", placeholder: "FwoGZXIvYXdzE...", type: "password" }];
      }
      return base;
    },
  },
  azure: {
    label: "Microsoft Azure",
    color: "text-blue-400",
    bgColor: "bg-blue-500/10",
    credTypes: [
      { value: "azure_client_secret", label: "App Registration (Client Secret)" },
      { value: "azure_managed_identity", label: "Managed Identity" },
      { value: "azure_cli", label: "Azure CLI Token" },
    ],
    fields: (type: string) => {
      if (type === "azure_client_secret") {
        return [
          { key: "clientId", label: "Client (Application) ID", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
          { key: "clientSecret", label: "Client Secret", placeholder: "~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", type: "password" },
          { key: "tenantId", label: "Tenant ID", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
        ];
      }
      return [{ key: "token", label: "Bearer Token", placeholder: "eyJ0eXAiOiJKV1Qi...", type: "password" }];
    },
  },
  gcp: {
    label: "Google Cloud Platform",
    color: "text-green-400",
    bgColor: "bg-green-500/10",
    credTypes: [
      { value: "gcp_service_account_key", label: "Service Account Key (JSON)" },
      { value: "gcp_workload_identity", label: "Workload Identity Federation" },
      { value: "gcp_oauth", label: "OAuth 2.0 Token" },
    ],
    fields: (type: string) => {
      if (type === "gcp_service_account_key") {
        return [
          { key: "serviceAccountKey", label: "Service Account Key JSON", placeholder: '{"type":"service_account","project_id":"..."}', multiline: true },
        ];
      }
      return [{ key: "token", label: "Access Token", placeholder: "ya29.xxx...", type: "password" }];
    },
  },
} as const;

type Provider = keyof typeof PROVIDER_CONFIG;

export default function CloudCredentials() {
  const [activeTab, setActiveTab] = useState<string>("credentials");
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [newCred, setNewCred] = useState({
    provider: "aws" as Provider,
    credentialName: "",
    credentialType: "aws_access_key",
    credentialData: {} as Record<string, string>,
    accountId: "",
    region: "us-east-1",
  });

  const credentialsQuery = trpc.cloudCredentials.listCredentials.useQuery({});
  const enumRunsQuery = trpc.cloudCredentials.listEnumerationRuns.useQuery({});
  const statsQuery = trpc.cloudCredentials.getEnumerationStats.useQuery({});

  const addMutation = trpc.cloudCredentials.addCredential.useMutation({
    onSuccess: () => {
      toast.success("Credential stored (encrypted at rest)");
      credentialsQuery.refetch();
      statsQuery.refetch();
      setAddDialogOpen(false);
      setNewCred({ provider: "aws", credentialName: "", credentialType: "aws_access_key", credentialData: {}, accountId: "", region: "us-east-1" });
    },
    onError: (e) => toast.error(e.message),
  });

  const validateMutation = trpc.cloudCredentials.validateCredential.useMutation({
    onSuccess: (result) => {
      if (result.valid) {
        toast.success(`Credential valid: ${result.identity || "OK"}`);
      } else {
        toast.error(`Validation failed: ${result.error || "Unknown error"}`);
      }
      credentialsQuery.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  const deleteMutation = trpc.cloudCredentials.deleteCredential.useMutation({
    onSuccess: () => {
      toast.success("Credential deleted");
      credentialsQuery.refetch();
      statsQuery.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  const enumMutation = trpc.cloudCredentials.runEnumeration.useMutation({
    onSuccess: (result) => {
      toast.success(`Enumeration complete: ${result.summary.totalUsers} users, ${result.summary.totalRoles} roles, ${result.summary.totalMisconfigs} misconfigs`);
      enumRunsQuery.refetch();
      statsQuery.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  const credentials = credentialsQuery.data || [];
  const enumRuns = enumRunsQuery.data || [];
  const stats = statsQuery.data;

  const handleProviderChange = (provider: Provider) => {
    const firstType = PROVIDER_CONFIG[provider].credTypes[0].value;
    setNewCred(prev => ({ ...prev, provider, credentialType: firstType, credentialData: {} }));
  };

  const handleAddCredential = () => {
    addMutation.mutate({
      provider: newCred.provider,
      credentialName: newCred.credentialName,
      credentialType: newCred.credentialType as any,
      credentialData: newCred.credentialData,
      accountId: newCred.accountId || undefined,
      region: newCred.region || undefined,
    });
  };

  const statusBadge = (status: string | null) => {
    switch (status) {
      case "active": return <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30"><CheckCircle className="w-3 h-3 mr-1" />Active</Badge>;
      case "error": return <Badge className="bg-red-500/20 text-red-400 border-red-500/30"><XCircle className="w-3 h-3 mr-1" />Error</Badge>;
      case "expired": return <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30"><AlertTriangle className="w-3 h-3 mr-1" />Expired</Badge>;
      default: return <Badge variant="outline">Unknown</Badge>;
    }
  };

  const currentFields = PROVIDER_CONFIG[newCred.provider].fields(newCred.credentialType);

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Key className="w-6 h-6 text-amber-400" />
              Cloud Credential Vault
            </h1>
            <p className="text-muted-foreground mt-1">
              Manage encrypted cloud provider credentials for live IAM enumeration
            </p>
          </div>
          <Dialog open={addDialogOpen} onOpenChange={setAddDialogOpen}>
            <DialogTrigger asChild>
              <Button className="bg-amber-600 hover:bg-amber-700">
                <Plus className="w-4 h-4 mr-2" />Add Credential
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Add Cloud Credential</DialogTitle>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Credential Name</Label>
                  <Input
                    value={newCred.credentialName}
                    onChange={e => setNewCred(prev => ({ ...prev, credentialName: e.target.value }))}
                    placeholder="e.g., Production AWS - PentestRole"
                  />
                </div>
                <div>
                  <Label>Cloud Provider</Label>
                  <Select value={newCred.provider} onValueChange={(v) => handleProviderChange(v as Provider)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="aws">Amazon Web Services (AWS)</SelectItem>
                      <SelectItem value="azure">Microsoft Azure</SelectItem>
                      <SelectItem value="gcp">Google Cloud Platform (GCP)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Credential Type</Label>
                  <Select value={newCred.credentialType} onValueChange={(v) => setNewCred(prev => ({ ...prev, credentialType: v, credentialData: {} }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {PROVIDER_CONFIG[newCred.provider].credTypes.map(ct => (
                        <SelectItem key={ct.value} value={ct.value}>{ct.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                {currentFields.map(field => (
                  <div key={field.key}>
                    <Label>{field.label}</Label>
                    {"multiline" in field && field.multiline ? (
                      <textarea
                        className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono min-h-[100px]"
                        value={newCred.credentialData[field.key] || ""}
                        onChange={e => setNewCred(prev => ({ ...prev, credentialData: { ...prev.credentialData, [field.key]: e.target.value } }))}
                        placeholder={field.placeholder}
                      />
                    ) : (
                      <Input
                        type={"type" in field ? (field as any).type : "text"}
                        value={newCred.credentialData[field.key] || ""}
                        onChange={e => setNewCred(prev => ({ ...prev, credentialData: { ...prev.credentialData, [field.key]: e.target.value } }))}
                        placeholder={field.placeholder}
                      />
                    )}
                  </div>
                ))}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Account/Subscription ID</Label>
                    <Input
                      value={newCred.accountId}
                      onChange={e => setNewCred(prev => ({ ...prev, accountId: e.target.value }))}
                      placeholder="123456789012"
                    />
                  </div>
                  <div>
                    <Label>Region</Label>
                    <Input
                      value={newCred.region}
                      onChange={e => setNewCred(prev => ({ ...prev, region: e.target.value }))}
                      placeholder="us-east-1"
                    />
                  </div>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setAddDialogOpen(false)}>Cancel</Button>
                <Button onClick={handleAddCredential} disabled={addMutation.isPending || !newCred.credentialName}>
                  {addMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Shield className="w-4 h-4 mr-2" />}
                  Store Encrypted
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Stored Credentials</p>
                  <p className="text-3xl font-bold">{stats?.totalCredentials ?? 0}</p>
                </div>
                <Key className="w-8 h-8 text-amber-400 opacity-50" />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Enumeration Runs</p>
                  <p className="text-3xl font-bold">{stats?.totalEnumerationRuns ?? 0}</p>
                </div>
                <Play className="w-8 h-8 text-blue-400 opacity-50" />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Providers Connected</p>
                  <p className="text-3xl font-bold">
                    {new Set(credentials.map(c => c.provider)).size}
                  </p>
                </div>
                <Cloud className="w-8 h-8 text-green-400 opacity-50" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="credentials">Credentials</TabsTrigger>
            <TabsTrigger value="enumeration">Enumeration Runs</TabsTrigger>
          </TabsList>

          <TabsContent value="credentials" className="space-y-4">
            {credentials.length === 0 ? (
              <Card className="bg-card/50 border-border/50">
                <CardContent className="pt-6 text-center py-12">
                  <Key className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-30" />
                  <p className="text-muted-foreground">No credentials stored yet.</p>
                  <p className="text-sm text-muted-foreground mt-1">Add AWS, Azure, or GCP credentials to begin live IAM enumeration.</p>
                </CardContent>
              </Card>
            ) : (
              <div className="grid gap-4">
                {credentials.map(cred => {
                  const providerConf = PROVIDER_CONFIG[cred.provider as Provider];
                  return (
                    <Card key={cred.id} className="bg-card/50 border-border/50">
                      <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <div className={`p-2 rounded-lg ${providerConf?.bgColor || "bg-muted"}`}>
                              <Cloud className={`w-5 h-5 ${providerConf?.color || "text-muted-foreground"}`} />
                            </div>
                            <div>
                              <CardTitle className="text-base">{cred.credentialName}</CardTitle>
                              <CardDescription>
                                {providerConf?.label || cred.provider} · {cred.credentialType} · {cred.region || "default region"}
                              </CardDescription>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {statusBadge(cred.status)}
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4 text-sm text-muted-foreground">
                            {cred.accountId && <span>Account: {cred.accountId}</span>}
                            {cred.lastValidatedAt && <span>Validated: {new Date(cred.lastValidatedAt).toLocaleDateString()}</span>}
                            {cred.lastUsedAt && <span>Last used: {new Date(cred.lastUsedAt).toLocaleDateString()}</span>}
                          </div>
                          <div className="flex items-center gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => validateMutation.mutate({ credentialId: cred.id })}
                              disabled={validateMutation.isPending}
                            >
                              {validateMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                              <span className="ml-1">Validate</span>
                            </Button>
                            <Button
                              size="sm"
                              className="bg-blue-600 hover:bg-blue-700"
                              onClick={() => enumMutation.mutate({ credentialId: cred.id })}
                              disabled={enumMutation.isPending}
                            >
                              {enumMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                              <span className="ml-1">Enumerate</span>
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              className="text-red-400 hover:text-red-300"
                              onClick={() => { if (confirm("Delete this credential?")) deleteMutation.mutate({ credentialId: cred.id }); }}
                            >
                              <Trash2 className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            )}
          </TabsContent>

          <TabsContent value="enumeration" className="space-y-4">
            {enumRuns.length === 0 ? (
              <Card className="bg-card/50 border-border/50">
                <CardContent className="pt-6 text-center py-12">
                  <Server className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-30" />
                  <p className="text-muted-foreground">No enumeration runs yet.</p>
                  <p className="text-sm text-muted-foreground mt-1">Run an enumeration from the Credentials tab to discover cloud identities.</p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-3">
                {enumRuns.map(run => (
                  <Card key={run.id} className="bg-card/50 border-border/50">
                    <CardContent className="pt-4 pb-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <Badge variant="outline" className="uppercase">{run.provider}</Badge>
                          <span className="text-sm">
                            {run.status === "running" && <Badge className="bg-blue-500/20 text-blue-400"><Loader2 className="w-3 h-3 mr-1 animate-spin" />Running</Badge>}
                            {run.status === "completed" && <Badge className="bg-emerald-500/20 text-emerald-400"><CheckCircle className="w-3 h-3 mr-1" />Completed</Badge>}
                            {run.status === "partial" && <Badge className="bg-amber-500/20 text-amber-400"><AlertTriangle className="w-3 h-3 mr-1" />Partial</Badge>}
                            {run.status === "error" && <Badge className="bg-red-500/20 text-red-400"><XCircle className="w-3 h-3 mr-1" />Error</Badge>}
                          </span>
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {run.startedAt ? new Date(run.startedAt).toLocaleString() : ""}
                        </span>
                      </div>
                      {run.status !== "running" && (
                        <div className="mt-3 grid grid-cols-3 md:grid-cols-6 gap-3 text-center">
                          <div><p className="text-lg font-bold">{run.totalUsersFound ?? 0}</p><p className="text-xs text-muted-foreground">Users</p></div>
                          <div><p className="text-lg font-bold">{run.totalRolesFound ?? 0}</p><p className="text-xs text-muted-foreground">Roles</p></div>
                          <div><p className="text-lg font-bold">{run.totalGroupsFound ?? 0}</p><p className="text-xs text-muted-foreground">Groups</p></div>
                          <div><p className="text-lg font-bold">{run.totalPoliciesFound ?? 0}</p><p className="text-xs text-muted-foreground">Policies</p></div>
                          <div><p className="text-lg font-bold">{run.totalServiceAccountsFound ?? 0}</p><p className="text-xs text-muted-foreground">Service Accts</p></div>
                          <div><p className="text-lg font-bold text-red-400">{run.totalMisconfigsFound ?? 0}</p><p className="text-xs text-muted-foreground">Misconfigs</p></div>
                        </div>
                      )}
                      {(() => {
                        const errors = run.errorLog as string[] | null;
                        if (!errors || !Array.isArray(errors) || errors.length === 0) return null;
                        return (
                          <div className="mt-2 p-2 rounded bg-red-500/10 border border-red-500/20 text-xs text-red-400 font-mono">
                            {errors.slice(0, 3).map((err: string, i: number) => <div key={i}>{String(err)}</div>)}
                          </div>
                        );
                      })()}
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
