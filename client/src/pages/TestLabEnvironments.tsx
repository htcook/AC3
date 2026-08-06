import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import {
  Server, Plus, Trash2, RefreshCw, Cloud, Monitor, Globe,
  CheckCircle2, AlertTriangle, XCircle, Clock, Cpu,
} from "lucide-react";

export default function TestLabEnvironments() {
  // toast from sonner is already imported
  const [envType, setEnvType] = useState("simulated");
  const [envName, setEnvName] = useState("");
  const [targetTemplate, setTargetTemplate] = useState("dvwa");
  const [platform, setPlatform] = useState("linux");
  const [dropletSize, setDropletSize] = useState("s-1vcpu-1gb");

  const { data: environments, isLoading, refetch } = trpc.testLab.listEnvironments.useQuery();
  const createEnv = trpc.testLab.createEnvironment.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.environment?.name || "New environment"} is provisioning...`);
      refetch();
      setEnvName("");
    },
    onError: (err) => toast.error(err.message),
  });
  const destroyEnv = trpc.testLab.destroyEnvironment.useMutation({
    onSuccess: () => {
      toast.info("Environment Destroyed");
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const stateIcon = (state: string) => {
    switch (state) {
      case "running": return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
      case "provisioning": return <Clock className="h-4 w-4 text-amber-400 animate-spin" />;
      case "error": return <XCircle className="h-4 w-4 text-red-400" />;
      case "destroyed": return <Trash2 className="h-4 w-4 text-muted-foreground" />;
      default: return <AlertTriangle className="h-4 w-4 text-amber-400" />;
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/10 rounded-lg">
            <Server className="h-7 w-7 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Lab Environments</h1>
            <p className="text-muted-foreground">Provision and manage test targets for Ember agent testing</p>
          </div>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      {/* Create Environment */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Plus className="h-5 w-5" />
            Create Environment
          </CardTitle>
          <CardDescription>Spin up a new test target for Ember deployment and C2 validation</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Environment Type</label>
              <Select value={envType} onValueChange={setEnvType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="simulated">Simulated (Scan Server)</SelectItem>
                  <SelectItem value="digitalocean">DigitalOcean Droplet</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Name</label>
              <Input
                placeholder="my-test-lab"
                value={envName}
                onChange={(e) => setEnvName(e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Target Template</label>
              <Select value={targetTemplate} onValueChange={setTargetTemplate}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="dvwa">DVWA (Web Vulns)</SelectItem>
                  <SelectItem value="bwapp">bWAPP (Web App)</SelectItem>
                  <SelectItem value="mutillidae">Mutillidae (OWASP)</SelectItem>
                  <SelectItem value="webgoat">WebGoat (Java)</SelectItem>
                  <SelectItem value="juice-shop">Juice Shop (Modern)</SelectItem>
                  <SelectItem value="metasploitable">Metasploitable</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Platform</label>
              <Select value={platform} onValueChange={setPlatform}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="windows">Windows (Simulated)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end">
              <Button
                className="w-full"
                onClick={() => createEnv.mutate({
                  name: envName || `lab-${targetTemplate}-${Date.now().toString(36)}`,
                  type: envType as any,
                  targetTemplate,
                  platform: platform as any,
                  dropletSize: envType === "digitalocean" ? dropletSize : undefined,
                })}
                disabled={createEnv.isPending}
              >
                {createEnv.isPending ? <RefreshCw className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
                Create
              </Button>
            </div>
          </div>
          {envType === "digitalocean" && (
            <div className="mt-3 p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg">
              <p className="text-xs text-amber-400 flex items-center gap-2">
                <AlertTriangle className="h-3 w-3" />
                DigitalOcean environments incur real costs. Estimated: $0.007-$0.036/hr depending on size.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Environment List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {isLoading ? (
          [1, 2, 3, 4].map(i => (
            <Card key={i} className="animate-pulse">
              <CardContent className="p-6"><div className="h-24 bg-muted rounded" /></CardContent>
            </Card>
          ))
        ) : environments?.length ? (
          environments.map((env: any) => (
            <Card key={env.id} className={`border-l-4 ${
              env.state === "running" ? "border-l-emerald-500" :
              env.state === "provisioning" ? "border-l-amber-500" :
              env.state === "error" ? "border-l-red-500" : "border-l-muted"
            }`}>
              <CardContent className="p-4">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    {env.type === "digitalocean" ? (
                      <Cloud className="h-5 w-5 text-blue-400" />
                    ) : env.type === "scan_server" ? (
                      <Globe className="h-5 w-5 text-emerald-400" />
                    ) : (
                      <Monitor className="h-5 w-5 text-muted-foreground" />
                    )}
                    <div>
                      <p className="font-medium">{env.name}</p>
                      <p className="text-xs text-muted-foreground">{env.id}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {stateIcon(env.state)}
                    <Badge variant={env.state === "running" ? "default" : env.state === "error" ? "destructive" : "secondary"}>
                      {env.state}
                    </Badge>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                  <div className="p-2 bg-muted/30 rounded">
                    <span className="text-muted-foreground">Type:</span>{" "}
                    <span className="font-medium">{env.type}</span>
                  </div>
                  <div className="p-2 bg-muted/30 rounded">
                    <span className="text-muted-foreground">Platform:</span>{" "}
                    <span className="font-medium">{env.platform}</span>
                  </div>
                  <div className="p-2 bg-muted/30 rounded">
                    <span className="text-muted-foreground">Targets:</span>{" "}
                    <span className="font-medium">{env.targets?.length ?? 0}</span>
                  </div>
                  <div className="p-2 bg-muted/30 rounded">
                    <span className="text-muted-foreground">Agents:</span>{" "}
                    <span className="font-medium">{env.deployedAgents?.length ?? 0}</span>
                  </div>
                </div>

                {env.targets?.length > 0 && (
                  <div className="mb-3">
                    <p className="text-xs text-muted-foreground mb-1">Targets:</p>
                    <div className="flex flex-wrap gap-1">
                      {env.targets.slice(0, 4).map((t: any) => (
                        <Badge key={t.id} variant="outline" className="text-xs">
                          {t.name}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex gap-2">
                  {env.state !== "destroyed" && (
                    <Button
                      variant="destructive"
                      size="sm"
                      className="text-xs"
                      onClick={() => destroyEnv.mutate({ environmentId: env.id })}
                      disabled={destroyEnv.isPending}
                    >
                      <Trash2 className="h-3 w-3 mr-1" /> Destroy
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))
        ) : (
          <Card className="col-span-2">
            <CardContent className="p-12 text-center">
              <Server className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-30" />
              <p className="text-muted-foreground">No lab environments yet. Create one above to start testing.</p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
