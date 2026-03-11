import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Library,
  Brain,
  Shield,
  Target,
  Eye,
  ChevronRight,
  Layers,
  ArrowRight,
  FileText,
  Cpu,
  Globe2,
  Search,
  ShieldAlert,
  Zap,
  Network,
  Copy,
  Check,
} from "lucide-react";
import { toast } from "sonner";

// ─── Category Colors ────────────────────────────────────────────────────────

const CATEGORY_CONFIG: Record<string, { color: string; bg: string; icon: React.ElementType }> = {
  offensive: { color: "text-red-400", bg: "bg-red-500/10 border-red-500/20", icon: Target },
  social_engineering: { color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20", icon: Brain },
  recon: { color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20", icon: Search },
  evasion: { color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20", icon: ShieldAlert },
};

const PHASE_CONFIG: Record<string, { color: string; icon: React.ElementType }> = {
  recon: { color: "text-blue-400", icon: Search },
  enumeration: { color: "text-cyan-400", icon: Globe2 },
  vuln_detection: { color: "text-yellow-400", icon: Eye },
  exploitation: { color: "text-red-400", icon: Zap },
  post_exploitation: { color: "text-purple-400", icon: Network },
  reporting: { color: "text-gray-400", icon: FileText },
};

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function KnowledgeBase() {
  const [activeTab, setActiveTab] = useState("modules");
  const [selectedModuleId, setSelectedModuleId] = useState<string | null>(null);
  const [previewPlatform, setPreviewPlatform] = useState<"windows" | "linux" | "macos">("linux");
  const [previewPhase, setPreviewPhase] = useState<"recon" | "enumeration" | "vuln_detection" | "exploitation" | "post_exploitation" | "reporting">("exploitation");
  const [copiedId, setCopiedId] = useState<string | null>(null);


  const { data: modules, isLoading: modulesLoading } = trpc.knowledgeBase.listModules.useQuery();
  const { data: stats, isLoading: statsLoading } = trpc.knowledgeBase.getStats.useQuery();
  const { data: phaseMapping } = trpc.knowledgeBase.getPhaseMapping.useQuery();

  const { data: modulePreview, isLoading: previewLoading } = trpc.knowledgeBase.previewContext.useQuery(
    { moduleId: selectedModuleId!, platform: previewPlatform },
    { enabled: !!selectedModuleId }
  );

  const { data: phasePreview, isLoading: phasePreviewLoading } = trpc.knowledgeBase.previewPhaseContext.useQuery(
    {
      phase: previewPhase,
      platform: previewPlatform,
      hasFirewall: true,
      hasWAF: true,
      hasFileUpload: true,
      includePhishing: true,
    },
    { enabled: activeTab === "phases" }
  );

  const handleCopyContext = async (text: string, id: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedId(id);
    toast.success("Copied to clipboard");
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container max-w-7xl py-8 space-y-8">
        {/* Header */}
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-violet-500/20 to-indigo-500/20 border border-violet-500/30">
              <Library className="h-6 w-6 text-violet-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">LLM Knowledge Base</h1>
              <p className="text-muted-foreground text-sm">
                View and manage offensive security knowledge modules injected into LLM specialist prompts
              </p>
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        {statsLoading ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-24 rounded-xl" />)}
          </div>
        ) : stats ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard
              label="Knowledge Modules"
              value={stats.totalModules}
              icon={Layers}
              color="text-violet-400"
            />
            <StatCard
              label="Total Items"
              value={stats.totalItems}
              icon={FileText}
              color="text-blue-400"
            />
            <StatCard
              label="MITRE Techniques"
              value={stats.totalMitreTechniques}
              icon={Shield}
              color="text-red-400"
            />
            <StatCard
              label="Injection Points"
              value={stats.totalInjectionPoints}
              icon={Cpu}
              color="text-emerald-400"
            />
          </div>
        ) : null}

        {/* Main Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-muted/50 border border-border">
            <TabsTrigger value="modules">Modules</TabsTrigger>
            <TabsTrigger value="phases">Phase Mapping</TabsTrigger>
            <TabsTrigger value="preview">Context Preview</TabsTrigger>
          </TabsList>

          {/* ── Modules Tab ── */}
          <TabsContent value="modules" className="mt-6 space-y-4">
            {modulesLoading ? (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {[1, 2, 3, 4, 5, 6].map(i => <Skeleton key={i} className="h-48 rounded-xl" />)}
              </div>
            ) : modules ? (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {modules.map(mod => (
                  <ModuleCard
                    key={mod.id}
                    module={mod}
                    isSelected={selectedModuleId === mod.id}
                    onSelect={() => {
                      setSelectedModuleId(mod.id);
                      setActiveTab("preview");
                    }}
                  />
                ))}
              </div>
            ) : null}
          </TabsContent>

          {/* ── Phase Mapping Tab ── */}
          <TabsContent value="phases" className="mt-6 space-y-6">
            <div className="flex items-center gap-4 mb-4">
              <Select value={previewPlatform} onValueChange={(v: any) => setPreviewPlatform(v)}>
                <SelectTrigger className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Phase Flow Visualization */}
            <div className="space-y-3">
              {phaseMapping?.map((pm, idx) => {
                const config = PHASE_CONFIG[pm.phase] || { color: "text-gray-400", icon: FileText };
                const PhaseIcon = config.icon;
                const isActive = previewPhase === pm.phase;

                return (
                  <div key={pm.phase}>
                    <Card
                      className={`cursor-pointer transition-all duration-200 hover:border-primary/40 ${isActive ? "border-primary/60 bg-primary/5" : "border-border"}`}
                      onClick={() => setPreviewPhase(pm.phase as any)}
                    >
                      <CardContent className="py-4 px-5">
                        <div className="flex items-start gap-4">
                          <div className={`p-2 rounded-lg bg-muted/50 ${config.color}`}>
                            <PhaseIcon className="h-5 w-5" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-semibold text-sm uppercase tracking-wider">
                                {pm.phase.replace(/_/g, " ")}
                              </span>
                              <Badge variant="outline" className="text-xs">
                                {pm.modules.length} modules
                              </Badge>
                            </div>
                            <p className="text-xs text-muted-foreground mb-2">{pm.description}</p>
                            <div className="flex flex-wrap gap-1.5">
                              {pm.modules.map(modId => {
                                const mod = modules?.find(m => m.id === modId);
                                const cat = mod?.category || "offensive";
                                const catConfig = CATEGORY_CONFIG[cat] || CATEGORY_CONFIG.offensive;
                                return (
                                  <Badge
                                    key={modId}
                                    variant="outline"
                                    className={`text-[10px] ${catConfig.bg} ${catConfig.color} border`}
                                  >
                                    {modId.replace(/-/g, " ")}
                                  </Badge>
                                );
                              })}
                              {pm.modules.length === 0 && (
                                <span className="text-xs text-muted-foreground italic">No modules injected</span>
                              )}
                            </div>
                          </div>
                          <ChevronRight className={`h-4 w-4 text-muted-foreground transition-transform ${isActive ? "rotate-90" : ""}`} />
                        </div>
                      </CardContent>
                    </Card>

                    {/* Phase Context Preview */}
                    {isActive && (
                      <Card className="mt-2 border-primary/30 bg-muted/30">
                        <CardContent className="py-4 px-5">
                          <div className="flex items-center justify-between mb-3">
                            <span className="text-xs font-medium text-muted-foreground">
                              Composite Context for {pm.phase.replace(/_/g, " ").toUpperCase()}
                            </span>
                            {phasePreview && (
                              <div className="flex items-center gap-3">
                                <span className="text-xs text-muted-foreground">
                                  {phasePreview.charCount.toLocaleString()} chars / ~{phasePreview.estimatedTokens.toLocaleString()} tokens
                                </span>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-7 px-2"
                                  onClick={() => handleCopyContext(phasePreview.context, pm.phase)}
                                >
                                  {copiedId === pm.phase ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                                </Button>
                              </div>
                            )}
                          </div>
                          {phasePreviewLoading ? (
                            <Skeleton className="h-32 rounded-lg" />
                          ) : phasePreview ? (
                            <ScrollArea className="h-64 rounded-lg bg-background/50 border border-border">
                              <pre className="p-4 text-xs text-muted-foreground whitespace-pre-wrap font-mono leading-relaxed">
                                {phasePreview.context || "No context generated for this phase with current settings."}
                              </pre>
                            </ScrollArea>
                          ) : null}
                        </CardContent>
                      </Card>
                    )}

                    {/* Arrow between phases */}
                    {idx < (phaseMapping?.length || 0) - 1 && (
                      <div className="flex justify-center py-1">
                        <ArrowRight className="h-4 w-4 text-muted-foreground/40 rotate-90" />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </TabsContent>

          {/* ── Context Preview Tab ── */}
          <TabsContent value="preview" className="mt-6 space-y-4">
            <div className="flex items-center gap-4">
              <Select
                value={selectedModuleId || ""}
                onValueChange={v => setSelectedModuleId(v)}
              >
                <SelectTrigger className="w-72">
                  <SelectValue placeholder="Select a module..." />
                </SelectTrigger>
                <SelectContent>
                  {modules?.map(m => (
                    <SelectItem key={m.id} value={m.id}>
                      {m.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={previewPlatform} onValueChange={(v: any) => setPreviewPlatform(v)}>
                <SelectTrigger className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {selectedModuleId ? (
              <Card className="border-border">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">
                      {modules?.find(m => m.id === selectedModuleId)?.name || selectedModuleId}
                    </CardTitle>
                    {modulePreview && (
                      <div className="flex items-center gap-3">
                        <Badge variant="outline" className="text-xs">
                          {modulePreview.charCount.toLocaleString()} chars
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          ~{modulePreview.estimatedTokens.toLocaleString()} tokens
                        </Badge>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 px-2"
                          onClick={() => handleCopyContext(modulePreview.context, selectedModuleId)}
                        >
                          {copiedId === selectedModuleId ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                        </Button>
                      </div>
                    )}
                  </div>
                  <CardDescription className="text-xs">
                    Context output that gets injected into LLM system prompts
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {previewLoading ? (
                    <Skeleton className="h-64 rounded-lg" />
                  ) : modulePreview ? (
                    <ScrollArea className="h-[500px] rounded-lg bg-muted/30 border border-border">
                      <pre className="p-4 text-xs text-muted-foreground whitespace-pre-wrap font-mono leading-relaxed">
                        {modulePreview.context}
                      </pre>
                    </ScrollArea>
                  ) : (
                    <div className="h-64 flex items-center justify-center text-muted-foreground text-sm">
                      Select a module to preview its context output
                    </div>
                  )}
                </CardContent>
              </Card>
            ) : (
              <Card className="border-dashed border-2 border-muted-foreground/20">
                <CardContent className="py-16 text-center">
                  <Library className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
                  <p className="text-muted-foreground">Select a module to preview its context output</p>
                  <p className="text-xs text-muted-foreground/60 mt-1">
                    Or click "Preview" on any module card in the Modules tab
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

// ─── Sub-Components ─────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, color }: { label: string; value: number; icon: React.ElementType; color: string }) {
  return (
    <Card className="border-border">
      <CardContent className="py-4 px-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground font-medium">{label}</p>
            <p className="text-2xl font-bold mt-1">{value}</p>
          </div>
          <div className={`p-2.5 rounded-xl bg-muted/50 ${color}`}>
            <Icon className="h-5 w-5" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ModuleCard({ module, isSelected, onSelect }: {
  module: any;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const catConfig = CATEGORY_CONFIG[module.category] || CATEGORY_CONFIG.offensive;
  const CatIcon = catConfig.icon;

  return (
    <Card
      className={`cursor-pointer transition-all duration-200 hover:border-primary/40 hover:shadow-md ${isSelected ? "border-primary/60 ring-1 ring-primary/30" : "border-border"}`}
      onClick={onSelect}
    >
      <CardContent className="py-5 px-5 space-y-4">
        <div className="flex items-start justify-between">
          <div className={`p-2 rounded-lg ${catConfig.bg} border`}>
            <CatIcon className={`h-4 w-4 ${catConfig.color}`} />
          </div>
          <div className="flex items-center gap-1.5">
            <Badge
              variant="outline"
              className={`text-[10px] ${module.status === "active" ? "text-green-400 border-green-500/30 bg-green-500/10" : module.status === "beta" ? "text-yellow-400 border-yellow-500/30 bg-yellow-500/10" : "text-gray-400 border-gray-500/30 bg-gray-500/10"}`}
            >
              {module.status}
            </Badge>
          </div>
        </div>

        <div>
          <h3 className="font-semibold text-sm leading-tight">{module.name}</h3>
          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{module.description}</p>
        </div>

        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <FileText className="h-3 w-3" />
            <span>{module.itemCount} items</span>
            <span className="text-muted-foreground/30">|</span>
            <Shield className="h-3 w-3" />
            <span>{module.mitreTechniques.length} MITRE techniques</span>
          </div>

          <div className="flex flex-wrap gap-1">
            {module.phases.slice(0, 4).map((phase: string) => {
              const phaseConfig = PHASE_CONFIG[phase] || { color: "text-gray-400" };
              return (
                <Badge key={phase} variant="outline" className={`text-[10px] ${phaseConfig.color}`}>
                  {phase.replace(/_/g, " ")}
                </Badge>
              );
            })}
            {module.phases.length > 4 && (
              <Badge variant="outline" className="text-[10px]">+{module.phases.length - 4}</Badge>
            )}
          </div>

          <div className="flex items-center gap-1 text-[10px] text-muted-foreground/60">
            <Cpu className="h-3 w-3" />
            <span>Injected into: {module.injectedInto.join(", ")}</span>
          </div>
        </div>

        <Button variant="ghost" size="sm" className="w-full h-8 text-xs">
          Preview Context <ChevronRight className="h-3 w-3 ml-1" />
        </Button>
      </CardContent>
    </Card>
  );
}
