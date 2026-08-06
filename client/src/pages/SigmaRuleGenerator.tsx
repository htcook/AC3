import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import { toast } from "sonner";
import {
  FileCode2, Zap, Shield, Copy, Download, Loader2, Plus, Trash2,
  ChevronDown, ChevronRight, AlertTriangle, Search,
} from "lucide-react";
import AppShell from "@/components/AppShell";

const TACTIC_COLORS: Record<string, string> = {
  "initial-access": "bg-red-500/20 text-red-400",
  "execution": "bg-orange-500/20 text-orange-400",
  "persistence": "bg-yellow-500/20 text-yellow-400",
  "privilege-escalation": "bg-amber-500/20 text-amber-400",
  "defense-evasion": "bg-emerald-500/20 text-emerald-400",
  "credential-access": "bg-cyan-500/20 text-cyan-400",
  "discovery": "bg-blue-500/20 text-blue-400",
  "lateral-movement": "bg-indigo-500/20 text-indigo-400",
  "collection": "bg-violet-500/20 text-violet-400",
  "exfiltration": "bg-purple-500/20 text-purple-400",
  "command-and-control": "bg-pink-500/20 text-pink-400",
  "impact": "bg-rose-500/20 text-rose-400",
};

const LEVEL_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  informational: "bg-slate-500/20 text-slate-400 border-slate-500/30",
};

const FORMAT_LABELS: Record<string, string> = {
  sigma: "Sigma YAML",
  splunk_spl: "Splunk SPL",
  kql: "Microsoft KQL",
  elastic_eql: "Elastic EQL",
};

interface TechniqueInput {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  procedure: string;
  detectionGap: boolean;
}

export default function SigmaRuleGenerator() {
  const [activeTab, setActiveTab] = useState("generate");
  const [techniques, setTechniques] = useState<TechniqueInput[]>([]);
  const [actorName, setActorName] = useState("");
  const [actorTechniques, setActorTechniques] = useState<{ id: string; name: string; tactic: string }[]>([]);
  const [generatedRuleSet, setGeneratedRuleSet] = useState<any>(null);
  const [exportFormat, setExportFormat] = useState<string>("sigma");
  const [expandedRules, setExpandedRules] = useState<Set<string>>(new Set());
  const [searchFilter, setSearchFilter] = useState("");

  const { data: templateData } = trpc.sigmaRules.getTemplates.useQuery();
  const { data: ruleSets } = trpc.sigmaRules.listRuleSets.useQuery();

  const generateMutation = trpc.sigmaRules.generateFromEmulation.useMutation({
    onSuccess: (data) => {
      setGeneratedRuleSet(data);
      toast.success(`Generated ${data.totalRules} Sigma rules`);
    },
    onError: (err) => toast.error(err.message),
  });

  const generateActorMutation = trpc.sigmaRules.generateForThreatActor.useMutation({
    onSuccess: (data) => {
      setGeneratedRuleSet(data);
      toast.success(`Generated ${data.totalRules} rules for ${actorName}`);
    },
    onError: (err) => toast.error(err.message),
  });

  const exportRuleSetQuery = trpc.sigmaRules.exportRuleSet.useQuery(
    { ruleSetId: generatedRuleSet?.id || "", format: exportFormat as any },
    { enabled: !!generatedRuleSet?.id },
  );

  const addTechnique = () => {
    setTechniques(prev => [...prev, {
      techniqueId: "", techniqueName: "", tactic: "", procedure: "", detectionGap: false,
    }]);
  };

  const updateTechnique = (index: number, field: keyof TechniqueInput, value: any) => {
    setTechniques(prev => prev.map((t, i) => i === index ? { ...t, [field]: value } : t));
  };

  const removeTechnique = (index: number) => {
    setTechniques(prev => prev.filter((_, i) => i !== index));
  };

  const addFromTemplate = (template: any) => {
    setTechniques(prev => [...prev, {
      techniqueId: template.techniqueId,
      techniqueName: template.techniqueName,
      tactic: template.tactic,
      procedure: "",
      detectionGap: false,
    }]);
    toast.success(`Added ${template.techniqueId}`);
  };

  const handleGenerate = () => {
    const valid = techniques.filter(t => t.techniqueId && t.techniqueName && t.tactic);
    if (valid.length === 0) {
      toast.error("Add at least one technique");
      return;
    }
    generateMutation.mutate({ techniques: valid });
  };

  const handleGenerateForActor = () => {
    if (!actorName.trim() || actorTechniques.length === 0) {
      toast.error("Provide actor name and at least one technique");
      return;
    }
    generateActorMutation.mutate({ actorName, techniques: actorTechniques });
  };

  const toggleRule = (ruleId: string) => {
    setExpandedRules(prev => {
      const next = new Set(prev);
      next.has(ruleId) ? next.delete(ruleId) : next.add(ruleId);
      return next;
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  const filteredTemplates = useMemo(() => {
    if (!templateData?.templates) return [];
    if (!searchFilter) return templateData.templates;
    const lower = searchFilter.toLowerCase();
    return templateData.templates.filter(t =>
      (t.techniqueId || '').toLowerCase().includes(lower) ||
      (t.techniqueName || '').toLowerCase().includes(lower) ||
      (t.tactic || '').toLowerCase().includes(lower)
    );
  }, [templateData, searchFilter]);

  return (
      <AppShell activePath="/sigma-rules">
      <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <FileCode2 className="h-7 w-7 text-violet-400" />
          Sigma Rule Generator
        </h1>
        <p className="text-muted-foreground mt-1">
          Auto-generate detection rules from ATT&CK techniques, emulation results, and threat actor TTPs
        </p>
      </div>

      {/* Coverage Stats */}
      {templateData?.coverage && (
        <div className="grid grid-cols-4 gap-4">
          <Card>
            <CardContent className="p-4 text-center">
              <div className="text-3xl font-bold text-violet-400">{templateData.coverage.totalTemplates}</div>
              <div className="text-xs text-muted-foreground">Technique Templates</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 text-center">
              <div className="text-3xl font-bold text-cyan-400">{templateData.coverage.tactics.length}</div>
              <div className="text-xs text-muted-foreground">Tactics Covered</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 text-center">
              <div className="text-3xl font-bold text-amber-400">4</div>
              <div className="text-xs text-muted-foreground">Export Formats</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 text-center">
              <div className="text-3xl font-bold text-emerald-400">{ruleSets?.length || 0}</div>
              <div className="text-xs text-muted-foreground">Generated Sets</div>
            </CardContent>
          </Card>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="generate">Generate from Techniques</TabsTrigger>
          <TabsTrigger value="actor">Threat Actor Rules</TabsTrigger>
          <TabsTrigger value="templates">Template Library</TabsTrigger>
          <TabsTrigger value="results">Results</TabsTrigger>
        </TabsList>

        {/* Generate from Techniques */}
        <TabsContent value="generate" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Emulation Technique Inputs</CardTitle>
              <CardDescription>
                Add techniques from emulation results or gap analysis to generate targeted detection rules
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {techniques.map((tech, i) => (
                <div key={i} className="grid grid-cols-12 gap-2 items-center p-2 rounded bg-muted/20">
                  <Input
                    className="col-span-2"
                    placeholder="T1059.001"
                    value={tech.techniqueId}
                    onChange={e => updateTechnique(i, "techniqueId", e.target.value)}
                  />
                  <Input
                    className="col-span-3"
                    placeholder="Technique Name"
                    value={tech.techniqueName}
                    onChange={e => updateTechnique(i, "techniqueName", e.target.value)}
                  />
                  <Input
                    className="col-span-2"
                    placeholder="Tactic"
                    value={tech.tactic}
                    onChange={e => updateTechnique(i, "tactic", e.target.value)}
                  />
                  <Input
                    className="col-span-3"
                    placeholder="Procedure (optional)"
                    value={tech.procedure}
                    onChange={e => updateTechnique(i, "procedure", e.target.value)}
                  />
                  <div className="col-span-1 flex items-center gap-1">
                    <Checkbox
                      checked={tech.detectionGap}
                      onCheckedChange={(checked) => updateTechnique(i, "detectionGap", !!checked)}
                    />
                    <span className="text-xs">Gap</span>
                  </div>
                  <Button variant="ghost" size="icon" onClick={() => removeTechnique(i)} className="col-span-1">
                    <Trash2 className="h-4 w-4 text-red-400" />
                  </Button>
                </div>
              ))}
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={addTechnique}>
                  <Plus className="h-4 w-4 mr-1" /> Add Technique
                </Button>
                <Button
                  size="sm"
                  onClick={handleGenerate}
                  disabled={generateMutation.isPending || techniques.length === 0}
                >
                  {generateMutation.isPending ? (
                    <><Loader2 className="h-4 w-4 animate-spin mr-1" /> Generating...</>
                  ) : (
                    <><Zap className="h-4 w-4 mr-1" /> Generate Rules</>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Threat Actor Rules */}
        <TabsContent value="actor" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Threat Actor Detection Pack</CardTitle>
              <CardDescription>
                Generate a complete Sigma rule set targeting a specific threat actor's known TTPs
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium mb-1 block">Threat Actor Name</label>
                <Input
                  placeholder="e.g., APT29, Lazarus Group, FIN7"
                  value={actorName}
                  onChange={e => setActorName(e.target.value)}
                />
              </div>
              <div>
                <label className="text-sm font-medium mb-2 block">Actor Techniques</label>
                {actorTechniques.map((tech, i) => (
                  <div key={i} className="grid grid-cols-12 gap-2 items-center mb-2">
                    <Input
                      className="col-span-3"
                      placeholder="T1059.001"
                      value={tech.id}
                      onChange={e => {
                        const updated = [...actorTechniques];
                        updated[i] = { ...updated[i], id: e.target.value };
                        setActorTechniques(updated);
                      }}
                    />
                    <Input
                      className="col-span-4"
                      placeholder="Technique Name"
                      value={tech.name}
                      onChange={e => {
                        const updated = [...actorTechniques];
                        updated[i] = { ...updated[i], name: e.target.value };
                        setActorTechniques(updated);
                      }}
                    />
                    <Input
                      className="col-span-4"
                      placeholder="Tactic"
                      value={tech.tactic}
                      onChange={e => {
                        const updated = [...actorTechniques];
                        updated[i] = { ...updated[i], tactic: e.target.value };
                        setActorTechniques(updated);
                      }}
                    />
                    <Button
                      variant="ghost" size="icon" className="col-span-1"
                      onClick={() => setActorTechniques(prev => prev.filter((_, idx) => idx !== i))}
                    >
                      <Trash2 className="h-4 w-4 text-red-400" />
                    </Button>
                  </div>
                ))}
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => setActorTechniques(prev => [...prev, { id: "", name: "", tactic: "" }])}>
                    <Plus className="h-4 w-4 mr-1" /> Add Technique
                  </Button>
                  <Button
                    size="sm"
                    onClick={handleGenerateForActor}
                    disabled={generateActorMutation.isPending}
                  >
                    {generateActorMutation.isPending ? (
                      <><Loader2 className="h-4 w-4 animate-spin mr-1" /> Generating...</>
                    ) : (
                      <><Shield className="h-4 w-4 mr-1" /> Generate Actor Pack</>
                    )}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Template Library */}
        <TabsContent value="templates" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Technique Template Library</CardTitle>
              <CardDescription>
                {templateData?.coverage.totalTemplates || 0} pre-built detection templates across {templateData?.coverage.tactics.length || 0} tactics
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="relative mb-4">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  className="pl-9"
                  placeholder="Search techniques..."
                  value={searchFilter}
                  onChange={e => setSearchFilter(e.target.value)}
                />
              </div>

              {/* Tactic breakdown */}
              {templateData?.coverage.byTactic && (
                <div className="flex flex-wrap gap-1.5 mb-4">
                  {Object.entries(templateData.coverage.byTactic).map(([tactic, count]) => (
                    <Badge key={tactic} variant="outline" className={TACTIC_COLORS[tactic] || "bg-muted"}>
                      {tactic} ({count as number})
                    </Badge>
                  ))}
                </div>
              )}

              <div className="space-y-2">
                {filteredTemplates.map((template: any) => (
                  <div
                    key={template.techniqueId}
                    className="p-3 rounded-lg bg-muted/20 hover:bg-muted/30 flex items-center gap-3 transition-colors"
                  >
                    <Badge variant="outline" className="font-mono text-xs shrink-0">
                      {template.techniqueId}
                    </Badge>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium">{template.techniqueName}</div>
                      <div className="flex gap-1.5 mt-1">
                        <Badge variant="secondary" className={`text-xs ${TACTIC_COLORS[template.tactic] || ""}`}>
                          {template.tactic}
                        </Badge>
                        <Badge variant="secondary" className="text-xs">{template.logSource}</Badge>
                        <Badge variant="outline" className={`text-xs ${LEVEL_COLORS[template.level] || ""}`}>
                          {template.level}
                        </Badge>
                      </div>
                    </div>
                    <Button size="sm" variant="outline" onClick={() => addFromTemplate(template)}>
                      <Plus className="h-3 w-3 mr-1" /> Add
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Results */}
        <TabsContent value="results" className="space-y-4">
          {generatedRuleSet ? (
            <>
              {/* Rule Set Summary */}
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-lg">{generatedRuleSet.name}</CardTitle>
                      <CardDescription>{generatedRuleSet.description}</CardDescription>
                    </div>
                    <div className="flex gap-2">
                      <Select value={exportFormat} onValueChange={setExportFormat}>
                        <SelectTrigger className="w-44">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="sigma">Sigma YAML</SelectItem>
                          <SelectItem value="splunk_spl">Splunk SPL</SelectItem>
                          <SelectItem value="kql">Microsoft KQL</SelectItem>
                          <SelectItem value="elastic_eql">Elastic EQL</SelectItem>
                        </SelectContent>
                      </Select>
                      {exportRuleSetQuery.data && (
                        <Button
                          variant="outline"
                          onClick={() => copyToClipboard(exportRuleSetQuery.data.content)}
                        >
                          <Copy className="h-4 w-4 mr-1" /> Copy All
                        </Button>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="flex gap-4 text-sm">
                    <div><span className="text-muted-foreground">Total Rules:</span> <strong>{generatedRuleSet.totalRules}</strong></div>
                    {Object.entries(generatedRuleSet.byLevel).filter(([, v]) => (v as number) > 0).map(([level, count]) => (
                      <Badge key={level} variant="outline" className={LEVEL_COLORS[level] || ""}>
                        {level}: {count as number}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Individual Rules */}
              <div className="space-y-2">
                {generatedRuleSet.rules.map((rule: any) => {
                  const expanded = expandedRules.has(rule.id);
                  return (
                    <Card key={rule.id} className="overflow-hidden">
                      <div
                        className="p-3 flex items-center gap-3 cursor-pointer hover:bg-muted/20"
                        onClick={() => toggleRule(rule.id)}
                      >
                        <FileCode2 className="h-5 w-5 text-violet-400 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="font-medium text-sm truncate">{rule.title}</div>
                          <div className="flex gap-1.5 mt-0.5">
                            <Badge variant="outline" className="text-xs font-mono">{rule.techniqueId}</Badge>
                            <Badge variant="secondary" className={`text-xs ${TACTIC_COLORS[rule.tactic] || ""}`}>
                              {rule.tactic}
                            </Badge>
                            {rule.description.startsWith("[DETECTION GAP]") && (
                              <Badge variant="outline" className="text-xs bg-red-500/20 text-red-400">
                                <AlertTriangle className="h-3 w-3 mr-0.5" /> Gap
                              </Badge>
                            )}
                          </div>
                        </div>
                        <Badge variant="outline" className={LEVEL_COLORS[rule.level]}>
                          {rule.level}
                        </Badge>
                        <div className="text-xs text-muted-foreground">{rule.confidence}%</div>
                        {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                      </div>
                      {expanded && (
                        <div className="px-3 pb-3 pt-0 border-t border-border/50 space-y-3">
                          <p className="text-sm text-muted-foreground">{rule.description}</p>
                          <div className="grid grid-cols-3 gap-2 text-xs">
                            <div><span className="text-muted-foreground">Log Source:</span> {rule.logsource.category} / {rule.logsource.product}</div>
                            <div><span className="text-muted-foreground">Data Source:</span> {rule.dataSource}</div>
                            <div><span className="text-muted-foreground">Method:</span> {rule.generationMethod}</div>
                          </div>
                          {rule.falsepositives.length > 0 && (
                            <div className="text-xs">
                              <span className="text-muted-foreground">False Positives:</span>{" "}
                              {rule.falsepositives.join(", ")}
                            </div>
                          )}
                          {/* Export preview */}
                          <div className="bg-black/40 rounded p-3 font-mono text-xs overflow-x-auto whitespace-pre">
                            {exportRuleSetQuery.data
                              ? exportRuleSetQuery.data.content.split("---").find((_: string, i: number) =>
                                  generatedRuleSet.rules.indexOf(rule) === i
                                ) || "Loading..."
                              : "Loading..."}
                          </div>
                          <div className="flex gap-2">
                            {(["sigma", "splunk_spl", "kql", "elastic_eql"] as const).map(fmt => (
                              <Button key={fmt} variant="ghost" size="sm" className="text-xs" onClick={() => {
                                setExportFormat(fmt);
                                toast.success(`Switched to ${FORMAT_LABELS[fmt]}`);
                              }}>
                                {FORMAT_LABELS[fmt]}
                              </Button>
                            ))}
                          </div>
                        </div>
                      )}
                    </Card>
                  );
                })}
              </div>
            </>
          ) : (
            <Card>
              <CardContent className="p-12 text-center">
                <FileCode2 className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <h3 className="text-lg font-medium">No Rules Generated Yet</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Use the "Generate from Techniques" or "Threat Actor Rules" tabs to create detection rules
                </p>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
      </AppShell>
  );
}
