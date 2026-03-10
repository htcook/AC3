import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Shield, CheckCircle2, AlertTriangle, XCircle, Search,
  FileText, Clock, Hash, ArrowLeft, Lock, Eye, Download
} from "lucide-react";
import AppShell from "@/components/AppShell";
import { Link, useLocation } from "wouter";
import { getKsiLabel, getThemeLabel } from "@/lib/ksi-labels";

export default function ThreePaoReview() {
  const [search, setSearch] = useState("");
  const [selectedTheme, setSelectedTheme] = useState<string | null>(null);
  const [expandedKsi, setExpandedKsi] = useState<string | null>(null);
  const [, navigate] = useLocation();

  const reviewQuery = trpc.oscalExport.get3paoReviewData.useQuery();
  const data = reviewQuery.data;

  const filteredKsis = useMemo(() => {
    if (!data) return [];
    let ksis = data.ksis;
    if (selectedTheme) {
      ksis = ksis.filter(k => k.themeCode === selectedTheme);
    }
    if (search) {
      const q = search.toLowerCase();
      ksis = ksis.filter(k =>
        k.ksiId.toLowerCase().includes(q) ||
        (k.title || "").toLowerCase().includes(q) ||
        (k.themeName || "").toLowerCase().includes(q) ||
        (k.aceC3Module || "").toLowerCase().includes(q)
      );
    }
    return ksis;
  }, [data, selectedTheme, search]);

  const getSatisfactionBadge = (state: string) => {
    switch (state) {
      case "satisfied":
        return <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30"><CheckCircle2 className="w-3 h-3 mr-1" />Satisfied</Badge>;
      case "partially-satisfied":
        return <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30"><AlertTriangle className="w-3 h-3 mr-1" />Partial</Badge>;
      default:
        return <Badge className="bg-red-500/20 text-red-400 border-red-500/30"><XCircle className="w-3 h-3 mr-1" />Not Satisfied</Badge>;
    }
  };

  if (reviewQuery.isLoading) {
    return (
      <AppShell activePath="/3pao-review">
        <div className="flex items-center justify-center h-96">
          <div className="text-center space-y-3">
            <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full mx-auto" />
            <p className="text-muted-foreground">Loading 3PAO review data...</p>
          </div>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell activePath="/3pao-review">
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Link href="/oscal-export">
                <Button variant="ghost" size="sm"><ArrowLeft className="w-4 h-4 mr-1" /> Back to OSCAL Export</Button>
              </Link>
            </div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Eye className="h-7 w-7 text-blue-500" />
              3PAO Review Mode
            </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">
              Read-only assessment view for Third Party Assessment Organizations. This view provides a comprehensive summary of all KSI posture, evidence, validation results, and NIST SP 800-53 control mappings for FedRAMP authorization assessment.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-blue-400 border-blue-500/30">
              <Lock className="w-3 h-3 mr-1" /> Read-Only
            </Badge>
            <Badge variant="outline" className="text-muted-foreground">
              <Clock className="w-3 h-3 mr-1" /> {data ? new Date(data.generatedAt).toLocaleString() : "—"}
            </Badge>
          </div>
        </div>

        {/* Executive Summary */}
        {data && (
          <Card className="border-blue-500/20 bg-blue-500/5">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Shield className="w-5 h-5 text-blue-400" />
                Executive Summary
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold">{data.summary.totalKsis}</div>
                  <div className="text-xs text-muted-foreground">Total KSIs</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-emerald-400">{data.summary.satisfied}</div>
                  <div className="text-xs text-muted-foreground">Satisfied</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-amber-400">{data.summary.partiallySatisfied}</div>
                  <div className="text-xs text-muted-foreground">Partial</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-400">{data.summary.notSatisfied}</div>
                  <div className="text-xs text-muted-foreground">Not Satisfied</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold">{data.summary.totalEvidence}</div>
                  <div className="text-xs text-muted-foreground">Evidence Items</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold">{data.summary.totalValidationRuns}</div>
                  <div className="text-xs text-muted-foreground">Validation Runs</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold">{data.summary.totalNistMappings}</div>
                  <div className="text-xs text-muted-foreground">NIST Mappings</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold">{data.summary.totalOscalExports}</div>
                  <div className="text-xs text-muted-foreground">OSCAL Exports</div>
                </div>
              </div>
              <div className="mt-4">
                <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
                  <span>Overall Satisfaction</span>
                  <span>{data.summary.totalKsis > 0 ? Math.round(((data.summary.satisfied + data.summary.partiallySatisfied * 0.5) / data.summary.totalKsis) * 100) : 0}%</span>
                </div>
                <div className="h-3 bg-muted rounded-full overflow-hidden flex">
                  <div className="h-full bg-emerald-500" style={{ width: `${data.summary.totalKsis > 0 ? (data.summary.satisfied / data.summary.totalKsis) * 100 : 0}%` }} />
                  <div className="h-full bg-amber-500" style={{ width: `${data.summary.totalKsis > 0 ? (data.summary.partiallySatisfied / data.summary.totalKsis) * 100 : 0}%` }} />
                  <div className="h-full bg-red-500" style={{ width: `${data.summary.totalKsis > 0 ? (data.summary.notSatisfied / data.summary.totalKsis) * 100 : 0}%` }} />
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Theme Breakdown */}
        {data && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Theme Breakdown</CardTitle>
              <CardDescription>Click a theme to filter the KSI detail table below</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                <button
                  className={`p-3 rounded-lg border text-left transition-colors ${!selectedTheme ? "border-blue-500 bg-blue-500/10" : "border-border hover:bg-muted/50"}`}
                  onClick={() => setSelectedTheme(null)}
                >
                  <div className="text-sm font-medium">All Themes</div>
                  <div className="text-xs text-muted-foreground">{data.summary.totalKsis} KSIs</div>
                </button>
                {data.themes.map(theme => {
                  const pct = theme.total > 0 ? Math.round((theme.satisfied / theme.total) * 100) : 0;
                  return (
                    <button
                      key={theme.code}
                      className={`p-3 rounded-lg border text-left transition-colors ${selectedTheme === theme.code ? "border-blue-500 bg-blue-500/10" : "border-border hover:bg-muted/50"}`}
                      onClick={() => setSelectedTheme(theme.code === selectedTheme ? null : theme.code)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="text-xs font-mono text-muted-foreground">{theme.code}</div>
                        <div className={`text-xs font-bold ${pct >= 80 ? "text-emerald-400" : pct >= 50 ? "text-amber-400" : "text-red-400"}`}>{pct}%</div>
                      </div>
                      <div className="text-sm font-medium mt-0.5 truncate">{getThemeLabel(theme.code) || theme.name}</div>
                      <div className="flex items-center gap-1 mt-1 text-[10px]">
                        <span className="text-emerald-400">{theme.satisfied}</span>
                        <span className="text-muted-foreground">/</span>
                        <span className="text-amber-400">{theme.partial}</span>
                        <span className="text-muted-foreground">/</span>
                        <span className="text-red-400">{theme.notSatisfied}</span>
                      </div>
                      <Progress value={pct} className="h-1 mt-1.5" />
                    </button>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        )}

        {/* KSI Detail Table */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base">KSI Detail Assessment</CardTitle>
                <CardDescription>
                  {filteredKsis.length} KSIs {selectedTheme ? `in ${getThemeLabel(selectedTheme) || selectedTheme}` : "across all themes"}
                </CardDescription>
              </div>
              <div className="relative w-64">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search KSIs..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9"
                />
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="border rounded-lg overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b bg-muted/30">
                    <th className="text-left p-3 font-medium">KSI ID</th>
                    <th className="text-left p-3 font-medium">Title</th>
                    <th className="text-left p-3 font-medium">Theme</th>
                    <th className="text-center p-3 font-medium">Evidence</th>
                    <th className="text-center p-3 font-medium">Validations</th>
                    <th className="text-center p-3 font-medium">Status</th>
                    <th className="text-left p-3 font-medium">NIST Controls</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredKsis.map(ksi => (
                    <>
                      <tr
                        key={ksi.ksiId}
                        className="border-b hover:bg-muted/20 cursor-pointer transition-colors"
                        onClick={() => setExpandedKsi(expandedKsi === ksi.ksiId ? null : ksi.ksiId)}
                      >
                        <td className="p-3 font-mono text-xs">
                          <button
                            className="text-blue-400 hover:underline"
                            onClick={(e) => { e.stopPropagation(); navigate(`/ksi/${encodeURIComponent(ksi.ksiId)}`); }}
                          >
                            {ksi.ksiId}
                          </button>
                        </td>
                        <td className="p-3 max-w-xs truncate">{getKsiLabel(ksi.ksiId) || ksi.title}</td>
                        <td className="p-3">
                          <Badge variant="outline" className="text-xs">{ksi.themeCode}</Badge>
                        </td>
                        <td className="p-3 text-center">
                          <span className={ksi.evidenceCount > 0 ? "text-emerald-400 font-medium" : "text-muted-foreground"}>
                            {ksi.evidenceCount}
                          </span>
                        </td>
                        <td className="p-3 text-center">
                          <span className={ksi.validationRunCount > 0 ? "text-blue-400 font-medium" : "text-muted-foreground"}>
                            {ksi.validationRunCount}
                          </span>
                        </td>
                        <td className="p-3 text-center">{getSatisfactionBadge(ksi.satisfactionState)}</td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1">
                            {ksi.nistControls.slice(0, 3).map(c => (
                              <Badge key={c} variant="outline" className="text-[10px] font-mono">{c}</Badge>
                            ))}
                            {ksi.nistControls.length > 3 && (
                              <Badge variant="outline" className="text-[10px]">+{ksi.nistControls.length - 3}</Badge>
                            )}
                          </div>
                        </td>
                      </tr>
                      {expandedKsi === ksi.ksiId && (
                        <tr key={`${ksi.ksiId}-detail`} className="bg-muted/10">
                          <td colSpan={7} className="p-4">
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                              <div>
                                <div className="text-muted-foreground mb-1">Coverage Status</div>
                                <Badge variant="outline">{ksi.coverageStatus}</Badge>
                              </div>
                              <div>
                                <div className="text-muted-foreground mb-1">ACE C3 Module</div>
                                <span className="font-medium">{ksi.aceC3Module || "N/A"}</span>
                              </div>
                              <div>
                                <div className="text-muted-foreground mb-1">Validation Type</div>
                                <span className="font-medium">{ksi.validationType || "N/A"}</span>
                              </div>
                              <div>
                                <div className="text-muted-foreground mb-1">Frequency</div>
                                <span className="font-medium">{ksi.frequency || "N/A"}</span>
                              </div>
                              <div>
                                <div className="text-muted-foreground mb-1">Latest Evidence</div>
                                <span className="font-medium">{ksi.latestEvidenceDate ? new Date(ksi.latestEvidenceDate).toLocaleDateString() : "None"}</span>
                              </div>
                              <div>
                                <div className="text-muted-foreground mb-1">Latest Validation</div>
                                <span className="font-medium">{ksi.latestValidationDate ? new Date(ksi.latestValidationDate).toLocaleDateString() : "None"}</span>
                              </div>
                              <div>
                                <div className="text-muted-foreground mb-1">Validation Status</div>
                                <Badge variant={ksi.latestValidationStatus === "passed" ? "default" : ksi.latestValidationStatus === "failed" ? "destructive" : "outline"}>
                                  {ksi.latestValidationStatus}
                                </Badge>
                              </div>
                              <div>
                                <div className="text-muted-foreground mb-1">All NIST Controls</div>
                                <div className="flex flex-wrap gap-1">
                                  {ksi.nistControls.map(c => (
                                    <Badge key={c} variant="outline" className="text-[10px] font-mono">{c}</Badge>
                                  ))}
                                  {ksi.nistControls.length === 0 && <span className="text-muted-foreground">None mapped</span>}
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
              {filteredKsis.length === 0 && (
                <div className="text-center py-8 text-muted-foreground">
                  No KSIs match the current filter
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Recent OSCAL Exports */}
        {data && data.recentExports.length > 0 && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <FileText className="w-4 h-4" />
                Recent OSCAL Exports
              </CardTitle>
              <CardDescription>Previously generated compliance documents available for download</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {data.recentExports.map((exp: any) => (
                  <div key={exp.exportId} className="flex items-center justify-between py-2 border-b last:border-0">
                    <div className="flex items-center gap-3">
                      <Badge variant="outline" className="text-xs uppercase font-mono">{exp.documentType}</Badge>
                      <span className="text-sm">{exp.title}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      {exp.outputHash && (
                        <span className="font-mono flex items-center gap-1">
                          <Hash className="w-3 h-3" />
                          {exp.outputHash.slice(0, 12)}
                        </span>
                      )}
                      <span>{exp.createdAt ? new Date(exp.createdAt).toLocaleDateString() : "—"}</span>
                      <Badge variant={exp.status === "complete" ? "default" : exp.status === "failed" ? "destructive" : "outline"} className="text-[10px]">
                        {exp.status}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}
