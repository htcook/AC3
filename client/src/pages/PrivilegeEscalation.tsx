import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  ArrowUpDown, Brain, Server, Terminal, Cloud, Key,
  Shield, ChevronRight, Zap, AlertTriangle, CheckCircle2, BookOpen
} from "lucide-react";
import AppShell from "@/components/AppShell";

/** Privilege Escalation — Analyze enumeration output and find escalation paths.
 *  Paste WinPEAS, LinPEAS, or manual enumeration output and the AI will identify
 *  privilege escalation vectors, recommend techniques, and provide step-by-step exploitation guidance. */

export default function PrivilegeEscalation() {
  // Using sonner toast
  const [os, setOs] = useState("windows");
  const [enumOutput, setEnumOutput] = useState("");
  const [currentPriv, setCurrentPriv] = useState("user");

  const { data: techniques } = trpc.privesc.techniques.useQuery({ os });
  const { data: enumTools } = trpc.privesc.enumerationTools.useQuery({ os });
  const { data: kerberosAttacks } = trpc.privesc.kerberosAttacks.useQuery();
  const { data: cloudPrivesc } = trpc.privesc.cloudPrivesc.useQuery();
  const { data: knowledgeBase } = trpc.privesc.knowledgeBase.useQuery({ os });

  const quickAnalyze = trpc.privesc.quickAnalyze.useMutation({
    onSuccess: () => toast.success("Analysis Complete"),
  });

  const llmAnalyze = trpc.privesc.analyze.useMutation({
    onSuccess: () => toast.success("AI Analysis Complete"),
  });

  const handleQuickAnalyze = () => {
    quickAnalyze.mutate({ os, enumerationOutput: enumOutput || "SeImpersonatePrivilege enabled\nUnquoted service path: C:\\Program Files\\Vuln Service\\service.exe", currentPrivilege: currentPriv });
  };

  const handleLlmAnalyze = () => {
    llmAnalyze.mutate({ os, enumerationOutput: enumOutput || "SeImpersonatePrivilege enabled", currentPrivilege: currentPriv });
  };

  const analysis = llmAnalyze.data || quickAnalyze.data;

  return (
      <AppShell activePath="/privilege-escalation">
      <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <ArrowUpDown className="w-7 h-7 text-red-400" />
          Privilege Escalation
        </h1>
        <p className="text-muted-foreground mt-1">
          Analyze enumeration output to find privilege escalation paths. Paste WinPEAS, LinPEAS, or manual output and the AI identifies vectors, recommends techniques, and provides exploitation guidance.
        </p>
      </div>

      <Tabs defaultValue="analyzer" className="space-y-4">
        <TabsList className="bg-background/50 border">
          <TabsTrigger value="analyzer"><Brain className="w-4 h-4 mr-1" />ANALYZER</TabsTrigger>
          <TabsTrigger value="techniques"><Shield className="w-4 h-4 mr-1" />TECHNIQUES</TabsTrigger>
          <TabsTrigger value="kerberos"><Key className="w-4 h-4 mr-1" />KERBEROS</TabsTrigger>
          <TabsTrigger value="cloud"><Cloud className="w-4 h-4 mr-1" />CLOUD</TabsTrigger>
          <TabsTrigger value="tools"><Terminal className="w-4 h-4 mr-1" />ENUM TOOLS</TabsTrigger>
        </TabsList>

        <TabsContent value="analyzer" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Zap className="w-4 h-4 text-red-400" />
                  Analyze Enumeration Output
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Target OS</label>
                    <Select value={os} onValueChange={setOs}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="windows">Windows</SelectItem>
                        <SelectItem value="linux">Linux</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Current Privilege</label>
                    <Select value={currentPriv} onValueChange={setCurrentPriv}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="user">Standard User</SelectItem>
                        <SelectItem value="service">Service Account</SelectItem>
                        <SelectItem value="local_admin">Local Admin</SelectItem>
                        <SelectItem value="domain_user">Domain User</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Enumeration Output</label>
                  <Textarea value={enumOutput} onChange={e => setEnumOutput(e.target.value)}
                    placeholder={os === "windows"
                      ? "Paste WinPEAS output, whoami /priv, systeminfo, etc..."
                      : "Paste LinPEAS output, sudo -l, find / -perm -4000, etc..."}
                    rows={8} className="font-mono text-xs" />
                </div>
                <div className="flex gap-2">
                  <Button onClick={handleQuickAnalyze} variant="outline" className="flex-1" disabled={quickAnalyze.isPending}>
                    Quick Analyze
                  </Button>
                  <Button onClick={handleLlmAnalyze} className="flex-1 bg-red-600 hover:bg-red-700" disabled={llmAnalyze.isPending}>
                    <Brain className="w-4 h-4 mr-1" />{llmAnalyze.isPending ? "Analyzing..." : "AI Deep Analysis"}
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Findings</CardTitle>
              </CardHeader>
              <CardContent>
                {analysis ? (
                  <div className="space-y-3">
                    {analysis.findings?.map((finding: any, i: number) => (
                      <div key={i} className={`p-3 rounded-lg border ${finding.severity === "critical" ? "bg-red-500/10 border-red-500/30" : finding.severity === "high" ? "bg-orange-500/10 border-orange-500/30" : "bg-yellow-500/10 border-yellow-500/30"}`}>
                        <div className="flex items-center gap-2">
                          <AlertTriangle className={`w-4 h-4 ${finding.severity === "critical" ? "text-red-400" : finding.severity === "high" ? "text-orange-400" : "text-yellow-400"}`} />
                          <span className="text-sm font-medium">{finding.technique || finding.name}</span>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">{finding.description}</p>
                        {finding.exploitSteps && (
                          <div className="mt-2 space-y-1">
                            {finding.exploitSteps.slice(0, 3).map((step: string, j: number) => (
                              <div key={j} className="text-xs flex items-start gap-1">
                                <ChevronRight className="w-3 h-3 text-muted-foreground mt-0.5 shrink-0" />
                                <span>{step}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                    {analysis.reasoning && <p className="text-xs text-muted-foreground mt-2">{analysis.reasoning}</p>}
                  </div>
                ) : (
                  <div className="text-center text-muted-foreground py-8">
                    <ArrowUpDown className="w-10 h-10 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">Analyze output to see findings</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="techniques" className="space-y-4">
          {techniques ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {techniques.map((tech: any) => (
                <Card key={tech.id || tech.name}>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      {os === "windows" ? <Server className="w-4 h-4 text-blue-400" /> : <Terminal className="w-4 h-4 text-green-400" />}
                      {tech.name}
                    </CardTitle>
                    <div className="flex gap-1 flex-wrap">
                      {tech.severity && <Badge variant={tech.severity === "critical" ? "destructive" : "secondary"} className="text-xs">{tech.severity}</Badge>}
                      {tech.mitreTechnique && <Badge variant="outline" className="text-xs">{tech.mitreTechnique}</Badge>}
                    </div>
                  </CardHeader>
                  <CardContent>
                    <p className="text-xs text-muted-foreground">{tech.description}</p>
                    {tech.command && <pre className="text-xs text-green-400 font-mono mt-2 p-1 rounded bg-black/30">{tech.command}</pre>}
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <div className="text-center text-muted-foreground py-12">Loading techniques...</div>
          )}
        </TabsContent>

        <TabsContent value="kerberos" className="space-y-4">
          {kerberosAttacks ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {kerberosAttacks.map((attack: any) => (
                <Card key={attack.id || attack.name}>
                  <CardHeader>
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Key className="w-4 h-4 text-yellow-400" />
                      {attack.name}
                    </CardTitle>
                    {attack.mitreTechnique && <Badge variant="outline" className="text-xs w-fit">{attack.mitreTechnique}</Badge>}
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <p className="text-xs text-muted-foreground">{attack.description}</p>
                    {attack.prerequisites && (
                      <div>
                        <span className="text-xs font-medium">Prerequisites:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {attack.prerequisites.map((p: string, i: number) => (
                            <Badge key={i} variant="secondary" className="text-xs">{p}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {attack.tools && (
                      <div>
                        <span className="text-xs font-medium">Tools:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {attack.tools.map((t: string, i: number) => (
                            <Badge key={i} variant="outline" className="text-xs">{t}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {attack.steps && (
                      <div className="space-y-1">
                        {attack.steps.slice(0, 4).map((step: string, i: number) => (
                          <div key={i} className="text-xs flex items-start gap-1">
                            <ChevronRight className="w-3 h-3 text-yellow-400 mt-0.5 shrink-0" />
                            <span>{step}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <div className="text-center text-muted-foreground py-12">Loading Kerberos attacks...</div>
          )}
        </TabsContent>

        <TabsContent value="cloud" className="space-y-4">
          {cloudPrivesc ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {cloudPrivesc.map((path: any) => (
                <Card key={path.id || path.name}>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Cloud className="w-4 h-4 text-cyan-400" />
                      {path.name}
                    </CardTitle>
                    <Badge variant="outline" className="text-xs w-fit">{path.provider || "multi-cloud"}</Badge>
                  </CardHeader>
                  <CardContent>
                    <p className="text-xs text-muted-foreground">{path.description}</p>
                    {path.impact && <p className="text-xs text-red-400 mt-1">Impact: {path.impact}</p>}
                    {path.detection && <p className="text-xs text-yellow-400 mt-1">Detection: {path.detection}</p>}
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <div className="text-center text-muted-foreground py-12">Loading cloud privesc paths...</div>
          )}
        </TabsContent>

        <TabsContent value="tools" className="space-y-4">
          {enumTools ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {enumTools.map((tool: any) => (
                <Card key={tool.id || tool.name}>
                  <CardHeader>
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-green-400" />
                      {tool.name}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <p className="text-xs text-muted-foreground">{tool.description}</p>
                    {tool.command && <pre className="text-xs text-green-400 font-mono p-2 rounded bg-black/30">{tool.command}</pre>}
                    {tool.url && (
                      <a href={tool.url} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline">
                        {tool.url}
                      </a>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <div className="text-center text-muted-foreground py-12">Loading enumeration tools...</div>
          )}
        </TabsContent>
      </Tabs>
    </div>
      </AppShell>
  );
}
