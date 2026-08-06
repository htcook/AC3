/**
 * Incident Response Runbook
 *
 * Interactive IR playbook that maps CloudWatch alarm triggers to specific
 * response procedures and escalation paths. Supports CRUD operations,
 * severity filtering, search, and seeding default entries from the monitoring stack.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  AlertTriangle, Shield, Search, Plus, Loader2, BookOpen,
  ChevronRight, Terminal, Users, Clock, Zap, Copy, CheckCircle2,
  XCircle, Eye, Trash2, Edit, BarChart3, ArrowUp, ArrowDown,
  Phone, Mail, MessageSquare, Activity, Flame, Server,
  CircleDot, RefreshCw, Download, Filter,
} from "lucide-react";

// ─── Types ──────────────────────────────────────────────────────────
interface ResponseStep {
  order: number;
  title: string;
  description: string;
  command?: string;
  automated: boolean;
  estimatedMinutes: number;
}

interface EscalationLevel {
  level: number;
  role: string;
  contactMethod: string;
  timeoutMinutes: number;
  description: string;
}

// ─── Constants ──────────────────────────────────────────────────────
const SEVERITY_CONFIG: Record<string, { color: string; bg: string; icon: typeof Flame }> = {
  critical: { color: "text-red-500", bg: "bg-red-500/10 border-red-500/30", icon: Flame },
  high: { color: "text-orange-500", bg: "bg-orange-500/10 border-orange-500/30", icon: AlertTriangle },
  medium: { color: "text-yellow-500", bg: "bg-yellow-500/10 border-yellow-500/30", icon: Activity },
  low: { color: "text-blue-500", bg: "bg-blue-500/10 border-blue-500/30", icon: CircleDot },
  informational: { color: "text-slate-400", bg: "bg-slate-500/10 border-slate-500/30", icon: Eye },
};

const CATEGORY_ICONS: Record<string, typeof Server> = {
  infrastructure: Server,
  application: Zap,
  security: Shield,
  performance: BarChart3,
  availability: Activity,
};

// ─── Subcomponents ──────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.informational;
  return (
    <Badge variant="outline" className={`${cfg.color} border-current/30 uppercase text-[10px] font-semibold`}>
      {severity}
    </Badge>
  );
}

function CategoryBadge({ category }: { category: string }) {
  const Icon = CATEGORY_ICONS[category] || Activity;
  return (
    <Badge variant="secondary" className="gap-1 text-xs">
      <Icon className="h-3 w-3" />
      {category}
    </Badge>
  );
}

function CopyableCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative group">
      <pre className="bg-black/80 text-green-400 text-xs p-3 rounded-md overflow-x-auto font-mono leading-relaxed">
        {command}
      </pre>
      <Button
        variant="ghost"
        size="icon"
        className="absolute top-1 right-1 h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
        onClick={() => {
          navigator.clipboard.writeText(command);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        }}
      >
        {copied ? <CheckCircle2 className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
      </Button>
    </div>
  );
}

function ResponseStepsTimeline({ steps }: { steps: ResponseStep[] }) {
  return (
    <div className="space-y-4">
      {steps.sort((a, b) => a.order - b.order).map((step, idx) => (
        <div key={step.order} className="flex gap-3">
          <div className="flex flex-col items-center">
            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold ${
              step.automated ? "bg-blue-500/20 text-blue-400 border border-blue-500/40" : "bg-muted text-muted-foreground border border-border"
            }`}>
              {step.order}
            </div>
            {idx < steps.length - 1 && <div className="w-px flex-1 bg-border mt-1" />}
          </div>
          <div className="flex-1 pb-4">
            <div className="flex items-center gap-2">
              <span className="font-medium text-sm">{step.title}</span>
              {step.automated && (
                <Badge variant="outline" className="text-[10px] text-blue-400 border-blue-400/40">
                  <Zap className="h-2.5 w-2.5 mr-0.5" /> Auto
                </Badge>
              )}
              <span className="text-xs text-muted-foreground ml-auto">
                <Clock className="h-3 w-3 inline mr-0.5" />
                ~{step.estimatedMinutes}m
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">{step.description}</p>
            {step.command && (
              <div className="mt-2">
                <CopyableCommand command={step.command} />
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function EscalationPathDisplay({ path }: { path: EscalationLevel[] }) {
  const contactIcon = (method: string) => {
    if (method.toLowerCase().includes("phone")) return <Phone className="h-3 w-3" />;
    if (method.toLowerCase().includes("email")) return <Mail className="h-3 w-3" />;
    if (method.toLowerCase().includes("slack")) return <MessageSquare className="h-3 w-3" />;
    return <Users className="h-3 w-3" />;
  };

  return (
    <div className="space-y-2">
      {path.sort((a, b) => a.level - b.level).map((level, idx) => (
        <div key={level.level} className="flex items-start gap-3">
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold shrink-0 ${
            level.level === 1 ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/40" :
            level.level === 2 ? "bg-orange-500/20 text-orange-400 border border-orange-500/40" :
            "bg-red-500/20 text-red-400 border border-red-500/40"
          }`}>
            L{level.level}
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <span className="font-medium text-sm">{level.role}</span>
              <span className="text-xs text-muted-foreground flex items-center gap-1">
                {contactIcon(level.contactMethod)}
                {level.contactMethod}
              </span>
              <span className="text-xs text-muted-foreground ml-auto">
                Timeout: {level.timeoutMinutes}m
              </span>
            </div>
            <p className="text-xs text-muted-foreground">{level.description}</p>
          </div>
          {idx < path.length - 1 && (
            <ArrowDown className="h-3 w-3 text-muted-foreground mt-2 shrink-0" />
          )}
        </div>
      ))}
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────
export default function IncidentResponseRunbook() {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [selectedEntryId, setSelectedEntryId] = useState<string | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  // ── Queries ──
  const { data: entries, isLoading, refetch } = trpc.irRunbook.list.useQuery(
    {
      severity: severityFilter !== "all" ? severityFilter as any : undefined,
      category: categoryFilter !== "all" ? categoryFilter as any : undefined,
      activeOnly: true,
    }
  );
  const { data: severitySummary } = trpc.irRunbook.severitySummary.useQuery();
  const { data: searchResults } = trpc.irRunbook.search.useQuery(
    { query: searchQuery },
    { enabled: searchQuery.length >= 2 }
  );

  const seedMutation = trpc.irRunbook.seedDefaults.useMutation({
    onSuccess: (data) => {
      toast.success(`Seeded ${data.count} default runbook entries`);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const deleteMutation = trpc.irRunbook.delete.useMutation({
    onSuccess: () => {
      toast.success("Entry deleted");
      refetch();
      setSelectedEntryId(null);
    },
    onError: (err) => toast.error(err.message),
  });

  const triggerMutation = trpc.irRunbook.recordTrigger.useMutation({
    onSuccess: () => {
      toast.success("Trigger recorded");
      refetch();
    },
  });

  // ── Derived data ──
  const displayEntries = searchQuery.length >= 2 ? searchResults : entries;
  const totalEstimatedTime = useMemo(() => {
    if (!displayEntries) return 0;
    return displayEntries.reduce((acc: number, e: any) => {
      const steps = (e.responseSteps as ResponseStep[]) || [];
      return acc + steps.reduce((s: number, st: ResponseStep) => s + st.estimatedMinutes, 0);
    }, 0);
  }, [displayEntries]);

  const selectedEntry = useMemo(() => {
    if (!selectedEntryId || !displayEntries) return null;
    return displayEntries.find((e: any) => e.entryId === selectedEntryId);
  }, [selectedEntryId, displayEntries]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <BookOpen className="h-6 w-6 text-primary" />
          Incident Response Runbook
        </h1>
        <p className="text-muted-foreground mt-1">
          Interactive playbook mapping CloudWatch alarm triggers to response procedures and escalation paths.
          Each entry provides step-by-step remediation commands and a tiered escalation chain.
        </p>
      </div>

      {/* Severity Summary Cards */}
      {severitySummary && (
        <div className="grid grid-cols-6 gap-3">
          {[
            { label: "Total", value: severitySummary.total, color: "text-foreground" },
            { label: "Critical", value: severitySummary.critical, color: "text-red-500" },
            { label: "High", value: severitySummary.high, color: "text-orange-500" },
            { label: "Medium", value: severitySummary.medium, color: "text-yellow-500" },
            { label: "Low", value: severitySummary.low, color: "text-blue-500" },
            { label: "Info", value: severitySummary.informational, color: "text-slate-400" },
          ].map((s) => (
            <Card key={s.label}>
              <CardContent className="pt-3 pb-2 text-center">
                <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{s.label}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Controls */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search alarms, descriptions, owners..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="informational">Informational</SelectItem>
          </SelectContent>
        </Select>
        <Select value={categoryFilter} onValueChange={setCategoryFilter}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            <SelectItem value="infrastructure">Infrastructure</SelectItem>
            <SelectItem value="application">Application</SelectItem>
            <SelectItem value="security">Security</SelectItem>
            <SelectItem value="performance">Performance</SelectItem>
            <SelectItem value="availability">Availability</SelectItem>
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          size="sm"
          onClick={() => seedMutation.mutate()}
          disabled={seedMutation.isPending}
          className="gap-1.5"
        >
          {seedMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
          Seed Defaults
        </Button>
      </div>

      {/* Main Content: List + Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left: Entry List */}
        <div className="lg:col-span-2">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !displayEntries || displayEntries.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <BookOpen className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
                <p className="text-muted-foreground">No runbook entries found.</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Click "Seed Defaults" to populate entries from the monitoring stack alarms.
                </p>
              </CardContent>
            </Card>
          ) : (
            <ScrollArea className="h-[600px]">
              <div className="space-y-2 pr-2">
                {displayEntries.map((entry: any) => {
                  const cfg = SEVERITY_CONFIG[entry.severity] || SEVERITY_CONFIG.informational;
                  const isSelected = selectedEntryId === entry.entryId;
                  return (
                    <Card
                      key={entry.entryId}
                      className={`cursor-pointer transition-all hover:shadow-md ${
                        isSelected ? `ring-2 ring-primary ${cfg.bg}` : "hover:bg-muted/30"
                      }`}
                      onClick={() => setSelectedEntryId(entry.entryId)}
                    >
                      <CardContent className="pt-3 pb-3">
                        <div className="flex items-start justify-between gap-2">
                          <div className="min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-medium text-sm truncate">{entry.alarmName}</span>
                              <SeverityBadge severity={entry.severity} />
                            </div>
                            <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                              {entry.triggerDescription}
                            </p>
                            <div className="flex items-center gap-3 mt-2">
                              <CategoryBadge category={entry.category} />
                              {entry.triggerCount > 0 && (
                                <span className="text-[10px] text-muted-foreground">
                                  Triggered {entry.triggerCount}x
                                </span>
                              )}
                              {entry.owner && (
                                <span className="text-[10px] text-muted-foreground">
                                  {entry.owner}
                                </span>
                              )}
                            </div>
                          </div>
                          <ChevronRight className={`h-4 w-4 shrink-0 mt-1 transition-transform ${
                            isSelected ? "rotate-90 text-primary" : "text-muted-foreground"
                          }`} />
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </ScrollArea>
          )}
        </div>

        {/* Right: Detail Panel */}
        <div className="lg:col-span-3">
          {!selectedEntry ? (
            <Card className="h-[600px] flex items-center justify-center">
              <div className="text-center">
                <Eye className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
                <p className="text-muted-foreground">Select a runbook entry to view details</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Click any alarm entry on the left to see response procedures and escalation paths.
                </p>
              </div>
            </Card>
          ) : (
            <ScrollArea className="h-[600px]">
              <div className="space-y-4 pr-2">
                {/* Entry Header */}
                <Card>
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between">
                      <div>
                        <CardTitle className="text-lg flex items-center gap-2">
                          {(() => {
                            const cfg = SEVERITY_CONFIG[selectedEntry.severity] || SEVERITY_CONFIG.informational;
                            const Icon = cfg.icon;
                            return <Icon className={`h-5 w-5 ${cfg.color}`} />;
                          })()}
                          {selectedEntry.alarmName}
                        </CardTitle>
                        <CardDescription className="mt-1">
                          {selectedEntry.triggerDescription}
                        </CardDescription>
                      </div>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          title="Record trigger"
                          onClick={() => triggerMutation.mutate({ entryId: selectedEntry.entryId })}
                        >
                          <RefreshCw className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-red-400 hover:text-red-500"
                          title="Delete entry"
                          onClick={() => {
                            if (confirm("Delete this runbook entry?")) {
                              deleteMutation.mutate({ entryId: selectedEntry.entryId });
                            }
                          }}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center gap-3 flex-wrap">
                      <SeverityBadge severity={selectedEntry.severity} />
                      <CategoryBadge category={selectedEntry.category} />
                      {selectedEntry.alarmPattern && (
                        <Badge variant="outline" className="font-mono text-[10px]">
                          {selectedEntry.alarmPattern}
                        </Badge>
                      )}
                      {selectedEntry.owner && (
                        <span className="text-xs text-muted-foreground flex items-center gap-1">
                          <Users className="h-3 w-3" /> {selectedEntry.owner}
                        </span>
                      )}
                      {selectedEntry.triggerCount > 0 && (
                        <span className="text-xs text-muted-foreground">
                          Triggered {selectedEntry.triggerCount}x
                          {selectedEntry.lastTriggeredAt && (
                            <> (last: {new Date(selectedEntry.lastTriggeredAt).toLocaleDateString()})</>
                          )}
                        </span>
                      )}
                    </div>
                  </CardContent>
                </Card>

                {/* Tabs: Response / Escalation / Related */}
                <Tabs defaultValue="response">
                  <TabsList className="w-full">
                    <TabsTrigger value="response" className="flex-1 gap-1">
                      <Terminal className="h-3.5 w-3.5" />
                      Response Steps
                    </TabsTrigger>
                    <TabsTrigger value="escalation" className="flex-1 gap-1">
                      <ArrowUp className="h-3.5 w-3.5" />
                      Escalation Path
                    </TabsTrigger>
                    <TabsTrigger value="related" className="flex-1 gap-1">
                      <Shield className="h-3.5 w-3.5" />
                      Mitigation
                    </TabsTrigger>
                  </TabsList>

                  <TabsContent value="response" className="mt-4">
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm">Response Procedure</CardTitle>
                        <CardDescription>
                          {((selectedEntry.responseSteps as ResponseStep[]) || []).length} steps — estimated{" "}
                          {((selectedEntry.responseSteps as ResponseStep[]) || []).reduce(
                            (a: number, s: ResponseStep) => a + s.estimatedMinutes, 0
                          )}m total
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <ResponseStepsTimeline steps={(selectedEntry.responseSteps as ResponseStep[]) || []} />
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="escalation" className="mt-4">
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm">Escalation Chain</CardTitle>
                        <CardDescription>
                          {((selectedEntry.escalationPath as EscalationLevel[]) || []).length} levels defined
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <EscalationPathDisplay path={(selectedEntry.escalationPath as EscalationLevel[]) || []} />
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="related" className="mt-4 space-y-4">
                    {/* Related Alarms */}
                    {selectedEntry.relatedAlarms && (selectedEntry.relatedAlarms as string[]).length > 0 && (
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Related Alarms</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex flex-wrap gap-2">
                            {(selectedEntry.relatedAlarms as string[]).map((alarm: string) => (
                              <Badge key={alarm} variant="outline" className="text-xs">
                                {alarm}
                              </Badge>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    )}

                    {/* Mitigation Actions */}
                    {selectedEntry.mitigationActions && (selectedEntry.mitigationActions as string[]).length > 0 && (
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Mitigation Actions</CardTitle>
                          <CardDescription>Immediate actions to reduce impact</CardDescription>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-1.5">
                            {(selectedEntry.mitigationActions as string[]).map((action: string, i: number) => (
                              <li key={i} className="flex items-start gap-2 text-sm">
                                <Zap className="h-3.5 w-3.5 text-yellow-500 mt-0.5 shrink-0" />
                                {action}
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>
                    )}

                    {/* Prevention Measures */}
                    {selectedEntry.preventionMeasures && (selectedEntry.preventionMeasures as string[]).length > 0 && (
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Prevention Measures</CardTitle>
                          <CardDescription>Long-term fixes to prevent recurrence</CardDescription>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-1.5">
                            {(selectedEntry.preventionMeasures as string[]).map((measure: string, i: number) => (
                              <li key={i} className="flex items-start gap-2 text-sm">
                                <Shield className="h-3.5 w-3.5 text-emerald-500 mt-0.5 shrink-0" />
                                {measure}
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>
                    )}
                  </TabsContent>
                </Tabs>
              </div>
            </ScrollArea>
          )}
        </div>
      </div>
    </div>
  );
}
