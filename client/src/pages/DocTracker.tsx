import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  FileText,
  Camera,
  GitCompare,
  AlertTriangle,
  CheckCircle2,
  Clock,
  BookOpen,
  Shield,
  Users,
  Building2,
  Cpu,
  RefreshCw,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { toast } from "sonner";

export default function DocTracker() {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set());

  const manifest = trpc.docTracker.getManifest.useQuery();
  const latestSnapshot = trpc.docTracker.getLatestSnapshot.useQuery();
  const snapshotList = trpc.docTracker.listSnapshots.useQuery();

  const takeSnapshotMutation = trpc.docTracker.takeSnapshot.useMutation({
    onSuccess: (data) => {
      toast.success(`Snapshot taken: ${data.stats.routes} routes, ${data.stats.routers} routers, ${data.stats.schemaTables} tables, ${data.stats.serverLibs} libs, ${data.stats.pages} pages`);
      latestSnapshot.refetch();
      snapshotList.refetch();
    },
    onError: (err) => toast.error(`Snapshot failed: ${err.message}`),
  });

  const generateReportMutation = trpc.docTracker.generateReport.useMutation({
    onSuccess: (data) => {
      if (data.isFirstSnapshot) {
        toast.info("First snapshot taken. Run again after platform changes to detect doc updates.");
      } else if (data.report && data.report.stats.totalChanges === 0) {
        toast.success("All documentation is up to date!");
      } else {
        toast.warning(`${data.report?.stats.totalChanges} changes detected, ${data.report?.stats.sectionsAffected} doc sections affected`);
      }
      latestSnapshot.refetch();
      snapshotList.refetch();
    },
    onError: (err) => toast.error(`Report generation failed: ${err.message}`),
  });

  const toggleSection = (id: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const guideIcons: Record<string, React.ReactNode> = {
    admin: <Shield className="h-4 w-4" />,
    user: <Users className="h-4 w-4" />,
    "msp-mssp": <Building2 className="h-4 w-4" />,
    "ember-design": <Cpu className="h-4 w-4" />,
  };

  const guideLabels: Record<string, string> = {
    admin: "Admin Guide",
    user: "User Guide",
    "msp-mssp": "MSP/MSSP Guide",
    "ember-design": "Ember Design",
  };

  const severityColors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    moderate: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <BookOpen className="h-6 w-6 text-cyan-400" />
            Documentation Tracker
          </h1>
          <p className="text-muted-foreground mt-1">
            Track platform changes and identify documentation sections that need updating
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => takeSnapshotMutation.mutate()}
            disabled={takeSnapshotMutation.isPending}
          >
            <Camera className="h-4 w-4 mr-2" />
            {takeSnapshotMutation.isPending ? "Taking..." : "Take Snapshot"}
          </Button>
          <Button
            onClick={() => generateReportMutation.mutate()}
            disabled={generateReportMutation.isPending}
            className="bg-cyan-600 hover:bg-cyan-700"
          >
            <GitCompare className="h-4 w-4 mr-2" />
            {generateReportMutation.isPending ? "Analyzing..." : "Generate Report"}
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-card/50 border-border/50">
          <CardContent className="pt-4 pb-4">
            <div className="text-sm text-muted-foreground">Doc Sections</div>
            <div className="text-2xl font-bold">{manifest.data?.totalSections ?? "—"}</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="pt-4 pb-4">
            <div className="text-sm text-muted-foreground">Latest Snapshot</div>
            <div className="text-sm font-mono mt-1">
              {latestSnapshot.data
                ? new Date(latestSnapshot.data.timestamp).toLocaleDateString()
                : "None"}
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="pt-4 pb-4">
            <div className="text-sm text-muted-foreground">Platform Components</div>
            <div className="text-2xl font-bold">
              {latestSnapshot.data
                ? latestSnapshot.data.stats.routes +
                  latestSnapshot.data.stats.routers +
                  latestSnapshot.data.stats.schemaTables +
                  latestSnapshot.data.stats.serverLibs +
                  latestSnapshot.data.stats.pages
                : "—"}
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="pt-4 pb-4">
            <div className="text-sm text-muted-foreground">Saved Snapshots</div>
            <div className="text-2xl font-bold">{snapshotList.data?.length ?? "—"}</div>
          </CardContent>
        </Card>
      </div>

      {/* Report Output */}
      {generateReportMutation.data && (
        <Card className="border-cyan-500/30 bg-cyan-500/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5 text-cyan-400" />
              Documentation Update Report
            </CardTitle>
            <CardDescription>
              {generateReportMutation.data.isFirstSnapshot
                ? "First snapshot taken — no previous state to compare"
                : `${generateReportMutation.data.report?.stats.totalChanges ?? 0} platform changes detected`}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {generateReportMutation.data.report && (
              <div className="space-y-4">
                {/* Report Stats */}
                <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
                  <div className="text-center p-2 rounded bg-background/50">
                    <div className="text-lg font-bold">{generateReportMutation.data.report.stats.totalChanges}</div>
                    <div className="text-xs text-muted-foreground">Changes</div>
                  </div>
                  <div className="text-center p-2 rounded bg-red-500/10">
                    <div className="text-lg font-bold text-red-400">{generateReportMutation.data.report.stats.criticalUpdates}</div>
                    <div className="text-xs text-muted-foreground">Critical</div>
                  </div>
                  <div className="text-center p-2 rounded bg-amber-500/10">
                    <div className="text-lg font-bold text-amber-400">{generateReportMutation.data.report.stats.moderateUpdates}</div>
                    <div className="text-xs text-muted-foreground">Moderate</div>
                  </div>
                  <div className="text-center p-2 rounded bg-blue-500/10">
                    <div className="text-lg font-bold text-blue-400">{generateReportMutation.data.report.stats.lowUpdates}</div>
                    <div className="text-xs text-muted-foreground">Low</div>
                  </div>
                  <div className="text-center p-2 rounded bg-background/50">
                    <div className="text-lg font-bold text-amber-400">{generateReportMutation.data.report.stats.sectionsAffected}</div>
                    <div className="text-xs text-muted-foreground">Affected</div>
                  </div>
                  <div className="text-center p-2 rounded bg-background/50">
                    <div className="text-lg font-bold text-emerald-400">{generateReportMutation.data.report.stats.sectionsUpToDate}</div>
                    <div className="text-xs text-muted-foreground">Up to Date</div>
                  </div>
                </div>

                {/* Impact List */}
                {generateReportMutation.data.report.impacts.length > 0 && (
                  <div className="space-y-2 mt-4">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">Required Updates</h4>
                    {generateReportMutation.data.report.impacts.map((impact: any, i: number) => (
                      <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-background/50 border border-border/50">
                        <Badge className={severityColors[impact.severity] || ""} variant="outline">
                          {impact.severity}
                        </Badge>
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium">{impact.diff.details}</div>
                          <div className="text-xs text-muted-foreground mt-1">{impact.action}</div>
                          <div className="flex flex-wrap gap-1 mt-2">
                            {impact.affectedSections.map((section: any) => (
                              <Badge key={section.id} variant="secondary" className="text-xs">
                                {section.path}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {generateReportMutation.data.report.impacts.length === 0 && (
                  <div className="flex items-center gap-2 p-4 rounded-lg bg-emerald-500/10 text-emerald-400">
                    <CheckCircle2 className="h-5 w-5" />
                    <span>All documentation is up to date — no platform changes affect documented sections.</span>
                  </div>
                )}
              </div>
            )}

            {/* Markdown Report */}
            {generateReportMutation.data.markdown && (
              <details className="mt-4">
                <summary className="text-sm text-muted-foreground cursor-pointer hover:text-foreground">
                  View raw Markdown report
                </summary>
                <pre className="mt-2 p-4 rounded-lg bg-background/80 text-xs font-mono overflow-x-auto max-h-96 overflow-y-auto whitespace-pre-wrap">
                  {generateReportMutation.data.markdown}
                </pre>
              </details>
            )}
          </CardContent>
        </Card>
      )}

      {/* Manifest Tabs */}
      <Tabs defaultValue="admin">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="admin" className="flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5" />
            Admin ({manifest.data?.byGuide.admin ?? 0})
          </TabsTrigger>
          <TabsTrigger value="user" className="flex items-center gap-1.5">
            <Users className="h-3.5 w-3.5" />
            User ({manifest.data?.byGuide.user ?? 0})
          </TabsTrigger>
          <TabsTrigger value="msp-mssp" className="flex items-center gap-1.5">
            <Building2 className="h-3.5 w-3.5" />
            MSP/MSSP ({manifest.data?.byGuide["msp-mssp"] ?? 0})
          </TabsTrigger>
          <TabsTrigger value="ember-design" className="flex items-center gap-1.5">
            <Cpu className="h-3.5 w-3.5" />
            Ember ({manifest.data?.byGuide["ember-design"] ?? 0})
          </TabsTrigger>
        </TabsList>

        {(["admin", "user", "msp-mssp", "ember-design"] as const).map(guide => (
          <TabsContent key={guide} value={guide} className="space-y-2 mt-4">
            {manifest.data?.sections
              .filter(s => s.guide === guide)
              .map(section => (
                <Card key={section.id} className="bg-card/30 border-border/30">
                  <div
                    className="flex items-center gap-3 p-4 cursor-pointer hover:bg-accent/10 transition-colors"
                    onClick={() => toggleSection(section.id)}
                  >
                    {expandedSections.has(section.id) ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
                    )}
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm">{section.title}</div>
                      <div className="text-xs text-muted-foreground">{section.path}</div>
                    </div>
                    <Badge variant="secondary" className="text-xs shrink-0">
                      {section.covers.length} components
                    </Badge>
                  </div>
                  {expandedSections.has(section.id) && (
                    <div className="px-4 pb-4 pt-0">
                      <div className="border-t border-border/30 pt-3 space-y-1.5">
                        {section.covers.map((comp, i) => (
                          <div key={i} className="flex items-center gap-2 text-xs">
                            <Badge variant="outline" className="text-[10px] font-mono px-1.5">
                              {comp.type}
                            </Badge>
                            <span className="font-mono text-muted-foreground">{comp.id}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </Card>
              ))}
          </TabsContent>
        ))}
      </Tabs>

      {/* Snapshot History */}
      {snapshotList.data && snapshotList.data.length > 0 && (
        <Card className="bg-card/30 border-border/30">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Clock className="h-4 w-4" />
              Snapshot History
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {snapshotList.data.map((filename: string, i: number) => (
                <div key={filename} className="flex items-center gap-2 text-xs font-mono p-2 rounded hover:bg-accent/10">
                  {i === 0 && <Badge className="bg-cyan-500/20 text-cyan-400 border-cyan-500/30 text-[10px]">latest</Badge>}
                  <span className="text-muted-foreground">{filename}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
