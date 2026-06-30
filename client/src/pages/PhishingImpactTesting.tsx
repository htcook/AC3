import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { Mail, Send, Users, Target, Brain, BarChart3, Shield, AlertTriangle, CheckCircle2, Clock, Eye, MousePointer, FileWarning, TrendingDown, Zap, Building2 } from "lucide-react";

export default function PhishingImpactTesting() {
  const [activeTab, setActiveTab] = useState("campaigns");
  const [campaignName, setCampaignName] = useState("");
  const [targetOrg, setTargetOrg] = useState("");
  const [templateType, setTemplateType] = useState("credential_harvest");
  const [difficulty, setDifficulty] = useState("medium");
  const [aiSpearPhish, setAiSpearPhish] = useState(false);

  const campaigns = trpc.phishingImpact.listCampaigns.useQuery();
  const templates = trpc.phishingImpact.getTemplates.useQuery();
  const orgResilience = trpc.phishingImpact.getOrgResilience.useQuery();
  const stats = trpc.phishingImpact.dashboardStats.useQuery();

  const launchCampaign = trpc.phishingImpact.launchCampaign.useMutation({
    onSuccess: (data) => {
      toast.success(`Campaign "${data.name}" launched with ${data.targetCount} targets`);
      campaigns.refetch();
      stats.refetch();
      setCampaignName("");
      setTargetOrg("");
    },
  });

  const generateSpearPhish = trpc.phishingImpact.generateAISpearPhish.useMutation({
    onSuccess: (data) => {
      toast.success(`AI generated ${data.variants.length} spear phishing variants`);
    },
  });

  const difficultyColors: Record<string, string> = {
    easy: "text-emerald-400 border-emerald-500/30",
    medium: "text-amber-400 border-amber-500/30",
    hard: "text-orange-400 border-orange-500/30",
    expert: "text-red-400 border-red-500/30",
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Mail className="h-7 w-7 text-amber-400" />
            Phishing Impact Testing
          </h1>
          <p className="text-muted-foreground mt-1">AI-powered phishing simulations with real-time tracking, department analytics, and organizational resilience scoring</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => generateSpearPhish.mutate({ targetOrg: targetOrg || "Acme Corp", role: "Finance Manager", context: "quarterly budget review" })}>
          <Brain className="h-4 w-4 mr-2" /> Generate AI Spear Phish
        </Button>
      </div>

      {/* KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
        {[
          { label: "Campaigns", value: stats.data?.totalCampaigns ?? 0, icon: Send, color: "text-blue-400" },
          { label: "Emails Sent", value: stats.data?.totalEmailsSent ?? 0, icon: Mail, color: "text-cyan-400" },
          { label: "Opened", value: stats.data?.totalOpened ?? 0, icon: Eye, color: "text-amber-400" },
          { label: "Clicked", value: stats.data?.totalClicked ?? 0, icon: MousePointer, color: "text-orange-400" },
          { label: "Credentials", value: stats.data?.totalCredentials ?? 0, icon: FileWarning, color: "text-red-400" },
          { label: "Reported", value: stats.data?.totalReported ?? 0, icon: Shield, color: "text-emerald-400" },
          { label: "Resilience", value: `${stats.data?.avgResilience ?? 0}%`, icon: TrendingDown, color: "text-purple-400" },
          { label: "Departments", value: stats.data?.departmentsTargeted ?? 0, icon: Building2, color: "text-pink-400" },
        ].map((kpi) => (
          <Card key={kpi.label} className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-3 text-center">
              <kpi.icon className={`h-5 w-5 mx-auto mb-1 ${kpi.color}`} />
              <div className="text-xl font-bold">{kpi.value}</div>
              <div className="text-xs text-muted-foreground">{kpi.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* AI Spear Phish Results */}
      {generateSpearPhish.data && (
        <Card className="bg-gradient-to-r from-amber-950/30 to-orange-950/30 border-amber-800/40">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2"><Brain className="h-4 w-4 text-amber-400" /> AI-Generated Spear Phishing Variants</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {generateSpearPhish.data.variants.map((v, i) => (
              <div key={i} className="p-3 rounded bg-zinc-900/50 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-sm">{v.subject}</span>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={difficultyColors[v.difficulty]}>{v.difficulty}</Badge>
                    <Badge variant="outline" className="text-xs">Est. {v.estimatedClickRate}% click rate</Badge>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">{v.previewText}</p>
                <div className="flex gap-1 flex-wrap">
                  {v.techniques.map(t => <Badge key={t} variant="outline" className="text-xs">{t}</Badge>)}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Launch Panel */}
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-lg">Launch Phishing Campaign</CardTitle>
          <CardDescription>Configure and launch a phishing simulation campaign with real-time event tracking</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Campaign Name</label>
              <Input value={campaignName} onChange={e => setCampaignName(e.target.value)} placeholder="Q1 2026 Phishing Test" />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Target Organization</label>
              <Input value={targetOrg} onChange={e => setTargetOrg(e.target.value)} placeholder="Acme Corp" />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Template Type</label>
              <Select value={templateType} onValueChange={setTemplateType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="credential_harvest">Credential Harvest</SelectItem>
                  <SelectItem value="malware_download">Malware Download Sim</SelectItem>
                  <SelectItem value="mfa_bypass">MFA Bypass</SelectItem>
                  <SelectItem value="qr_code">QR Code Phishing</SelectItem>
                  <SelectItem value="voice_phishing">Vishing (Voice)</SelectItem>
                  <SelectItem value="sms_phishing">Smishing (SMS)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Difficulty</label>
              <Select value={difficulty} onValueChange={setDifficulty}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="easy">Easy (obvious red flags)</SelectItem>
                  <SelectItem value="medium">Medium (realistic)</SelectItem>
                  <SelectItem value="hard">Hard (targeted)</SelectItem>
                  <SelectItem value="expert">Expert (APT-level)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button
              onClick={() => launchCampaign.mutate({
                name: campaignName || "Phishing Test",
                targetOrg: targetOrg || "Test Org",
                templateType: templateType as any,
                difficulty: difficulty as any,
                aiSpearPhish,
              })}
              disabled={launchCampaign.isPending}
              className="bg-amber-600 hover:bg-amber-700"
            >
              <Send className="h-4 w-4 mr-2" /> Launch Campaign
            </Button>
          </div>
          <div className="mt-3 flex items-center gap-2">
            <input type="checkbox" id="ai-spear" checked={aiSpearPhish} onChange={e => setAiSpearPhish(e.target.checked)} className="rounded" />
            <label htmlFor="ai-spear" className="text-sm text-muted-foreground">Enable AI spear phishing (personalizes emails per target using OSINT data)</label>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="campaigns">Campaigns</TabsTrigger>
          <TabsTrigger value="resilience">Org Resilience</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
        </TabsList>

        <TabsContent value="campaigns" className="space-y-3 mt-4">
          {(!campaigns.data || campaigns.data.length === 0) ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-12 text-center text-muted-foreground">
                <Mail className="h-12 w-12 mx-auto mb-4 opacity-30" />
                <p>No campaigns yet. Launch a phishing simulation to begin testing organizational resilience.</p>
              </CardContent>
            </Card>
          ) : (
            campaigns.data.map(campaign => (
              <Card key={campaign.id} className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <span className="font-medium">{campaign.name}</span>
                      <span className="text-muted-foreground text-sm ml-2">— {campaign.targetOrg}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className={difficultyColors[campaign.difficulty]}>{campaign.difficulty}</Badge>
                      <Badge variant={campaign.status === "completed" ? "default" : campaign.status === "active" ? "secondary" : "outline"}>
                        {campaign.status}
                      </Badge>
                    </div>
                  </div>
                  {/* Funnel */}
                  <div className="grid grid-cols-5 gap-2 text-center text-sm">
                    {[
                      { label: "Sent", value: campaign.stats.sent, color: "bg-blue-500/20 text-blue-300" },
                      { label: "Opened", value: campaign.stats.opened, color: "bg-cyan-500/20 text-cyan-300" },
                      { label: "Clicked", value: campaign.stats.clicked, color: "bg-amber-500/20 text-amber-300" },
                      { label: "Submitted", value: campaign.stats.submitted, color: "bg-red-500/20 text-red-300" },
                      { label: "Reported", value: campaign.stats.reported, color: "bg-emerald-500/20 text-emerald-300" },
                    ].map(s => (
                      <div key={s.label} className={`p-2 rounded ${s.color}`}>
                        <div className="text-lg font-bold">{s.value}</div>
                        <div className="text-xs">{s.label}</div>
                      </div>
                    ))}
                  </div>
                  {campaign.status === "active" && (
                    <div className="mt-3">
                      <div className="flex justify-between text-xs text-muted-foreground mb-1">
                        <span>Campaign Progress</span>
                        <span>{Math.round(campaign.stats.sent > 0 ? (campaign.stats.opened / campaign.stats.sent) * 100 : 0)}% open rate</span>
                      </div>
                      <Progress value={campaign.stats.sent > 0 ? (campaign.stats.opened / campaign.stats.sent) * 100 : 0} className="h-1.5" />
                    </div>
                  )}
                  {/* Department breakdown */}
                  {campaign.departmentStats && campaign.departmentStats.length > 0 && (
                    <div className="mt-3 space-y-1">
                      <div className="text-xs text-muted-foreground">Department Breakdown</div>
                      {campaign.departmentStats.map(dept => (
                        <div key={dept.department} className="flex items-center gap-2 text-sm">
                          <span className="w-24 truncate text-muted-foreground">{dept.department}</span>
                          <Progress value={dept.clickRate} className="h-1.5 flex-1" />
                          <span className="text-xs w-16 text-right">{dept.clickRate}% click</span>
                          <Badge variant="outline" className={`text-xs ${dept.resilience >= 70 ? "text-emerald-400 border-emerald-500/30" : dept.resilience >= 40 ? "text-amber-400 border-amber-500/30" : "text-red-400 border-red-500/30"}`}>
                            {dept.resilience}% resilient
                          </Badge>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        <TabsContent value="resilience" className="mt-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2"><Shield className="h-5 w-5 text-emerald-400" /> Organizational Resilience Score</CardTitle>
              <CardDescription>Aggregate phishing resilience across all campaigns and departments</CardDescription>
            </CardHeader>
            <CardContent>
              {orgResilience.data ? (
                <div className="space-y-6">
                  <div className="flex items-center gap-8">
                    <div className="text-center">
                      <div className={`text-5xl font-bold ${orgResilience.data.overallScore >= 70 ? "text-emerald-400" : orgResilience.data.overallScore >= 40 ? "text-amber-400" : "text-red-400"}`}>
                        {orgResilience.data.overallScore}%
                      </div>
                      <div className="text-sm text-muted-foreground mt-1">Overall Resilience</div>
                    </div>
                    <div className="flex-1 space-y-2">
                      <div className="flex justify-between text-sm"><span>Awareness</span><span>{orgResilience.data.awarenessScore}%</span></div>
                      <Progress value={orgResilience.data.awarenessScore} className="h-2" />
                      <div className="flex justify-between text-sm"><span>Reporting</span><span>{orgResilience.data.reportingScore}%</span></div>
                      <Progress value={orgResilience.data.reportingScore} className="h-2" />
                      <div className="flex justify-between text-sm"><span>Response Time</span><span>{orgResilience.data.responseTimeScore}%</span></div>
                      <Progress value={orgResilience.data.responseTimeScore} className="h-2" />
                    </div>
                  </div>
                  {/* Department leaderboard */}
                  <div>
                    <h3 className="text-sm font-medium mb-2">Department Leaderboard</h3>
                    <div className="space-y-2">
                      {orgResilience.data.departments.map((dept, i) => (
                        <div key={dept.name} className="flex items-center gap-3 p-2 rounded bg-zinc-800/50">
                          <span className="text-muted-foreground w-6 text-right">#{i + 1}</span>
                          <Building2 className="h-4 w-4 text-muted-foreground" />
                          <span className="flex-1">{dept.name}</span>
                          <span className="text-sm text-muted-foreground">{dept.employees} employees</span>
                          <Badge variant="outline" className={`${dept.resilience >= 70 ? "text-emerald-400 border-emerald-500/30" : dept.resilience >= 40 ? "text-amber-400 border-amber-500/30" : "text-red-400 border-red-500/30"}`}>
                            {dept.resilience}%
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                  {/* Trend */}
                  <div>
                    <h3 className="text-sm font-medium mb-2">Resilience Trend (Last 6 Campaigns)</h3>
                    <div className="flex items-end gap-2 h-24">
                      {orgResilience.data.trend.map((point, i) => (
                        <div key={i} className="flex-1 flex flex-col items-center gap-1">
                          <div className={`w-full rounded-t ${point.score >= 70 ? "bg-emerald-500/40" : point.score >= 40 ? "bg-amber-500/40" : "bg-red-500/40"}`} style={{ height: `${point.score}%` }} />
                          <span className="text-xs text-muted-foreground">{point.score}%</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center text-muted-foreground p-8">
                  <Shield className="h-12 w-12 mx-auto mb-4 opacity-30" />
                  <p>Run phishing campaigns to build organizational resilience data.</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="templates" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {templates.data?.map(template => (
              <Card key={template.id} className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-2">
                    <Badge variant="outline" className="text-xs">{template.category}</Badge>
                    <Badge variant="outline" className={difficultyColors[template.difficulty]}>{template.difficulty}</Badge>
                  </div>
                  <h3 className="font-medium mb-1">{template.name}</h3>
                  <p className="text-sm text-muted-foreground mb-3">{template.description}</p>
                  <div className="flex gap-1 flex-wrap mb-3">
                    {template.techniques.map(t => <Badge key={t} variant="outline" className="text-xs">{t}</Badge>)}
                  </div>
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>Est. click rate: {template.estimatedClickRate}%</span>
                    <Button size="sm" variant="ghost" onClick={() => { setTemplateType(template.category); toast.info(`Template selected: ${template.name}`); }}>
                      Use Template
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
