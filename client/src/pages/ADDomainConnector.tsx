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
import { Switch } from "@/components/ui/switch";
import {
  Network, Server, Plus, Trash2, CheckCircle, XCircle,
  AlertTriangle, Play, Loader2, RefreshCw, Users, Shield,
  Lock, Globe, FolderTree
} from "lucide-react";

export default function ADDomainConnector() {
  const [activeTab, setActiveTab] = useState<string>("connections");
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [enumScopes, setEnumScopes] = useState<Record<number, string>>({});
  const getEnumScope = (connId: number) => enumScopes[connId] || "full";
  const setEnumScope = (connId: number, scope: string) => setEnumScopes(prev => ({ ...prev, [connId]: scope }));
  const [newConn, setNewConn] = useState({
    connectionName: "",
    serverHost: "",
    serverPort: 389,
    useTls: false,
    tlsRejectUnauthorized: true,
    baseDn: "",
    bindDn: "",
    bindPassword: "",
    domainName: "",
    searchScope: "sub" as "base" | "one" | "sub",
  });

  const connectionsQuery = trpc.adDomainConnector.listConnections.useQuery({});
  const enumRunsQuery = trpc.adDomainConnector.listEnumerationRuns.useQuery({});
  const statsQuery = trpc.adDomainConnector.getStats.useQuery({});

  const addMutation = trpc.adDomainConnector.addConnection.useMutation({
    onSuccess: () => {
      toast.success("Domain connection added (credentials encrypted)");
      connectionsQuery.refetch();
      statsQuery.refetch();
      setAddDialogOpen(false);
      setNewConn({
        connectionName: "", serverHost: "", serverPort: 389, useTls: false,
        tlsRejectUnauthorized: true, baseDn: "", bindDn: "", bindPassword: "",
        domainName: "", searchScope: "sub",
      });
    },
    onError: (e) => toast.error(e.message),
  });

  const testMutation = trpc.adDomainConnector.testConnection.useMutation({
    onSuccess: (result) => {
      if (result.success) {
        toast.success("LDAP connection successful");
      } else {
        toast.error(`Connection failed: ${result.message}`);
      }
      connectionsQuery.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  const deleteMutation = trpc.adDomainConnector.deleteConnection.useMutation({
    onSuccess: () => {
      toast.success("Connection deleted");
      connectionsQuery.refetch();
      statsQuery.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  const enumMutation = trpc.adDomainConnector.runEnumeration.useMutation({
    onSuccess: (result) => {
      const s = result.summary;
      toast.success(`AD enumeration complete: ${s.totalUsers} users, ${s.totalGroups} groups, ${s.totalComputers} computers`);
      if (result.attackSurface) {
        toast.info(`Risk Score: ${result.attackSurface.riskScore}/100 — ${result.attackSurface.kerberoastTargets} Kerberoastable, ${result.attackSurface.asrepRoastTargets} AS-REP Roastable`);
      }
      enumRunsQuery.refetch();
      statsQuery.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  const connections = connectionsQuery.data || [];
  const enumRuns = enumRunsQuery.data || [];
  const stats = statsQuery.data;

  const statusBadge = (status: string | null) => {
    switch (status) {
      case "connected": return <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30"><CheckCircle className="w-3 h-3 mr-1" />Connected</Badge>;
      case "error": return <Badge className="bg-red-500/20 text-red-400 border-red-500/30"><XCircle className="w-3 h-3 mr-1" />Error</Badge>;
      case "disconnected": return <Badge className="bg-zinc-500/20 text-zinc-400 border-zinc-500/30">Disconnected</Badge>;
      default: return <Badge variant="outline">Unknown</Badge>;
    }
  };

  const handleAdd = () => {
    addMutation.mutate({
      connectionName: newConn.connectionName,
      serverHost: newConn.serverHost,
      serverPort: newConn.serverPort,
      useTls: newConn.useTls,
      tlsRejectUnauthorized: newConn.tlsRejectUnauthorized,
      baseDn: newConn.baseDn,
      bindDn: newConn.bindDn || undefined,
      bindPassword: newConn.bindPassword || undefined,
      domainName: newConn.domainName,
      searchScope: newConn.searchScope,
    });
  };

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Network className="w-6 h-6 text-purple-400" />
              AD Domain Connector
            </h1>
            <p className="text-muted-foreground mt-1">
              LDAP/LDAPS integration for live Active Directory enumeration and attack surface analysis
            </p>
          </div>
          <Dialog open={addDialogOpen} onOpenChange={setAddDialogOpen}>
            <DialogTrigger asChild>
              <Button className="bg-purple-600 hover:bg-purple-700">
                <Plus className="w-4 h-4 mr-2" />Add Domain Connection
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Add LDAP Domain Connection</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 max-h-[60vh] overflow-y-auto pr-2">
                <div>
                  <Label>Connection Name</Label>
                  <Input
                    value={newConn.connectionName}
                    onChange={e => setNewConn(prev => ({ ...prev, connectionName: e.target.value }))}
                    placeholder="e.g., CORP.ACME.COM - Primary DC"
                  />
                </div>
                <div>
                  <Label>Domain Name</Label>
                  <Input
                    value={newConn.domainName}
                    onChange={e => setNewConn(prev => ({ ...prev, domainName: e.target.value }))}
                    placeholder="corp.acme.com"
                  />
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div className="col-span-2">
                    <Label>Server Host</Label>
                    <Input
                      value={newConn.serverHost}
                      onChange={e => setNewConn(prev => ({ ...prev, serverHost: e.target.value }))}
                      placeholder="dc01.corp.acme.com"
                    />
                  </div>
                  <div>
                    <Label>Port</Label>
                    <Input
                      type="number"
                      value={newConn.serverPort}
                      onChange={e => setNewConn(prev => ({ ...prev, serverPort: parseInt(e.target.value) || 389 }))}
                    />
                  </div>
                </div>
                <div>
                  <Label>Base DN</Label>
                  <Input
                    value={newConn.baseDn}
                    onChange={e => setNewConn(prev => ({ ...prev, baseDn: e.target.value }))}
                    placeholder="DC=corp,DC=acme,DC=com"
                  />
                </div>
                <div className="flex items-center gap-6">
                  <div className="flex items-center gap-2">
                    <Switch checked={newConn.useTls} onCheckedChange={v => setNewConn(prev => ({ ...prev, useTls: v, serverPort: v ? 636 : 389 }))} />
                    <Label>Use TLS (LDAPS)</Label>
                  </div>
                  {newConn.useTls && (
                    <div className="flex items-center gap-2">
                      <Switch checked={newConn.tlsRejectUnauthorized} onCheckedChange={v => setNewConn(prev => ({ ...prev, tlsRejectUnauthorized: v }))} />
                      <Label>Verify Certificate</Label>
                    </div>
                  )}
                </div>
                <div>
                  <Label>Bind DN (optional)</Label>
                  <Input
                    value={newConn.bindDn}
                    onChange={e => setNewConn(prev => ({ ...prev, bindDn: e.target.value }))}
                    placeholder="CN=svc-pentest,OU=Service Accounts,DC=corp,DC=acme,DC=com"
                  />
                </div>
                <div>
                  <Label>Bind Password (optional)</Label>
                  <Input
                    type="password"
                    value={newConn.bindPassword}
                    onChange={e => setNewConn(prev => ({ ...prev, bindPassword: e.target.value }))}
                    placeholder="••••••••"
                  />
                </div>
                <div>
                  <Label>Search Scope</Label>
                  <Select value={newConn.searchScope} onValueChange={v => setNewConn(prev => ({ ...prev, searchScope: v as any }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="sub">Subtree (Full Domain)</SelectItem>
                      <SelectItem value="one">One Level</SelectItem>
                      <SelectItem value="base">Base Only</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setAddDialogOpen(false)}>Cancel</Button>
                <Button onClick={handleAdd} disabled={addMutation.isPending || !newConn.connectionName || !newConn.serverHost || !newConn.baseDn}>
                  {addMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Lock className="w-4 h-4 mr-2" />}
                  Save Connection
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
                  <p className="text-sm text-muted-foreground">Domain Connections</p>
                  <p className="text-3xl font-bold">{stats?.totalConnections ?? 0}</p>
                </div>
                <Globe className="w-8 h-8 text-purple-400 opacity-50" />
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
                <FolderTree className="w-8 h-8 text-blue-400 opacity-50" />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Active Connections</p>
                  <p className="text-3xl font-bold">
                    {connections.filter(c => c.status === "connected").length}
                  </p>
                </div>
                <CheckCircle className="w-8 h-8 text-emerald-400 opacity-50" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="connections">Domain Connections</TabsTrigger>
            <TabsTrigger value="enumeration">Enumeration Runs</TabsTrigger>
          </TabsList>

          <TabsContent value="connections" className="space-y-4">
            {connections.length === 0 ? (
              <Card className="bg-card/50 border-border/50">
                <CardContent className="pt-6 text-center py-12">
                  <Network className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-30" />
                  <p className="text-muted-foreground">No domain connections configured.</p>
                  <p className="text-sm text-muted-foreground mt-1">Add an LDAP/LDAPS connection to begin enumerating Active Directory objects.</p>
                </CardContent>
              </Card>
            ) : (
              <div className="grid gap-4">
                {connections.map(conn => (
                  <Card key={conn.id} className="bg-card/50 border-border/50">
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="p-2 rounded-lg bg-purple-500/10">
                            <Server className="w-5 h-5 text-purple-400" />
                          </div>
                          <div>
                            <CardTitle className="text-base">{conn.connectionName}</CardTitle>
                            <CardDescription>
                              {conn.domainName} · {conn.serverHost}:{conn.serverPort} · {conn.useTls ? "LDAPS" : "LDAP"}
                            </CardDescription>
                          </div>
                        </div>
                        {statusBadge(conn.status)}
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-col gap-3">
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span>Base DN: <code className="text-xs bg-muted px-1 rounded">{conn.baseDn}</code></span>
                          {conn.bindDn && <span>Bind: <code className="text-xs bg-muted px-1 rounded">{conn.bindDn.split(",")[0]}</code></span>}
                          {conn.lastConnectedAt && <span>Last connected: {new Date(conn.lastConnectedAt).toLocaleDateString()}</span>}
                        </div>
                        {conn.errorMessage && (
                          <div className="p-2 rounded bg-red-500/10 border border-red-500/20 text-xs text-red-400 font-mono">
                            {conn.errorMessage}
                          </div>
                        )}
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Label className="text-xs text-muted-foreground">Scope:</Label>
                            <Select value={getEnumScope(conn.id)} onValueChange={(v) => setEnumScope(conn.id, v)}>
                              <SelectTrigger className="w-[140px] h-8 text-xs"><SelectValue /></SelectTrigger>
                              <SelectContent>
                                <SelectItem value="full">Full Domain</SelectItem>
                                <SelectItem value="users">Users Only</SelectItem>
                                <SelectItem value="groups">Groups Only</SelectItem>
                                <SelectItem value="computers">Computers Only</SelectItem>
                                <SelectItem value="gpos">GPOs Only</SelectItem>
                                <SelectItem value="trusts">Trusts Only</SelectItem>
                                <SelectItem value="spns">SPNs Only</SelectItem>
                                <SelectItem value="certificates">Cert Templates</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="flex items-center gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => testMutation.mutate({ connectionId: conn.id })}
                              disabled={testMutation.isPending}
                            >
                              {testMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                              <span className="ml-1">Test</span>
                            </Button>
                            <Button
                              size="sm"
                              className="bg-purple-600 hover:bg-purple-700"
                              onClick={() => enumMutation.mutate({ connectionId: conn.id, scope: getEnumScope(conn.id) as any })}
                              disabled={enumMutation.isPending}
                            >
                              {enumMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                              <span className="ml-1">Enumerate</span>
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              className="text-red-400 hover:text-red-300"
                              onClick={() => { if (confirm("Delete this connection?")) deleteMutation.mutate({ connectionId: conn.id }); }}
                            >
                              <Trash2 className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </TabsContent>

          <TabsContent value="enumeration" className="space-y-4">
            {enumRuns.length === 0 ? (
              <Card className="bg-card/50 border-border/50">
                <CardContent className="pt-6 text-center py-12">
                  <Users className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-30" />
                  <p className="text-muted-foreground">No enumeration runs yet.</p>
                  <p className="text-sm text-muted-foreground mt-1">Run an enumeration from the Connections tab to discover AD objects.</p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-3">
                {enumRuns.map(run => (
                  <Card key={run.id} className="bg-card/50 border-border/50">
                    <CardContent className="pt-4 pb-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-3">
                          <Badge variant="outline" className="uppercase">{run.scope || "full"}</Badge>
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
                        <>
                          <div className="grid grid-cols-4 md:grid-cols-7 gap-3 text-center">
                            <div><p className="text-lg font-bold">{run.totalUsersFound ?? 0}</p><p className="text-xs text-muted-foreground">Users</p></div>
                            <div><p className="text-lg font-bold">{run.totalGroupsFound ?? 0}</p><p className="text-xs text-muted-foreground">Groups</p></div>
                            <div><p className="text-lg font-bold">{run.totalComputersFound ?? 0}</p><p className="text-xs text-muted-foreground">Computers</p></div>
                            <div><p className="text-lg font-bold">{run.totalGposFound ?? 0}</p><p className="text-xs text-muted-foreground">GPOs</p></div>
                            <div><p className="text-lg font-bold">{run.totalOusFound ?? 0}</p><p className="text-xs text-muted-foreground">OUs</p></div>
                            <div><p className="text-lg font-bold">{run.totalTrustsFound ?? 0}</p><p className="text-xs text-muted-foreground">Trusts</p></div>
                            <div><p className="text-lg font-bold">{run.totalSpnsFound ?? 0}</p><p className="text-xs text-muted-foreground">SPNs</p></div>
                          </div>
                          {/* Attack Surface Indicators */}
                          {(run.privilegedUsersFound || run.kerberoastableFound || run.asrepRoastableFound) && (
                            <div className="mt-3 flex items-center gap-4 p-2 rounded bg-red-500/5 border border-red-500/10">
                              <Shield className="w-4 h-4 text-red-400" />
                              <div className="flex items-center gap-4 text-xs">
                                {(run.privilegedUsersFound ?? 0) > 0 && (
                                  <span className="text-amber-400">{run.privilegedUsersFound} privileged</span>
                                )}
                                {(run.kerberoastableFound ?? 0) > 0 && (
                                  <span className="text-red-400">{run.kerberoastableFound} Kerberoastable</span>
                                )}
                                {(run.asrepRoastableFound ?? 0) > 0 && (
                                  <span className="text-red-400">{run.asrepRoastableFound} AS-REP Roastable</span>
                                )}
                              </div>
                            </div>
                          )}
                          {/* Risk Score */}
                          {run.results && typeof run.results === "object" && "attackSurface" in (run.results as any) && (
                            <div className="mt-2 flex items-center gap-3">
                              <span className="text-xs text-muted-foreground">Risk Score:</span>
                              <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${
                                    (run.results as any).attackSurface.riskScore > 70 ? "bg-red-500" :
                                    (run.results as any).attackSurface.riskScore > 40 ? "bg-amber-500" : "bg-emerald-500"
                                  }`}
                                  style={{ width: `${(run.results as any).attackSurface.riskScore}%` }}
                                />
                              </div>
                              <span className="text-sm font-bold">{(run.results as any).attackSurface.riskScore}/100</span>
                            </div>
                          )}
                        </>
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
