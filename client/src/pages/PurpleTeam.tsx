import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import {
  Shield, Plus, Search, Eye, EyeOff, AlertTriangle,
  CheckCircle, XCircle, BarChart3, Target, Trash2
} from "lucide-react";

const TACTICS = [
  "reconnaissance", "resource-development", "initial-access",
  "execution", "persistence", "privilege-escalation",
  "defense-evasion", "credential-access", "discovery",
  "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact"
];

export default function PurpleTeam() {
  const [search, setSearch] = useState("");
  const [tacticFilter, setTacticFilter] = useState("");
  const [gapFilter, setGapFilter] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [activeTab, setActiveTab] = useState<"tests" | "matrix" | "scores">("tests");

  // Form state
  const [newTechniqueId, setNewTechniqueId] = useState("");
  const [newTechniqueName, setNewTechniqueName] = useState("");
  const [newTactic, setNewTactic] = useState("execution");
  const [newDetected, setNewDetected] = useState(false);
  const [newNotes, setNewNotes] = useState("");

  const searchInput = useMemo(() => ({
    search: search || undefined,
    tactic: tacticFilter || undefined,
    isGap: gapFilter === "gaps" ? true : gapFilter === "detected" ? false : undefined,
  }), [search, tacticFilter, gapFilter]);

  const { data: tests, isLoading, refetch } = trpc.purpleTeam.listTests.useQuery(searchInput);
  const { data: stats } = trpc.purpleTeam.stats.useQuery();
  const { data: matrix } = trpc.purpleTeam.coverageMatrix.useQuery(undefined, { enabled: activeTab === "matrix" });
  const { data: scores } = trpc.purpleTeam.listScores.useQuery(undefined, { enabled: activeTab === "scores" });

  const createMutation = trpc.purpleTeam.createTest.useMutation({
    onSuccess: () => {
      toast.success("Detection test created");
      setShowCreateDialog(false);
      setNewTechniqueId("");
      setNewTechniqueName("");
      setNewNotes("");
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const updateMutation = trpc.purpleTeam.updateTest.useMutation({
    onSuccess: () => {
      toast.success("Test updated");
      refetch();
    },
  });

  const deleteMutation = trpc.purpleTeam.deleteTest.useMutation({
    onSuccess: () => {
      toast.success("Test deleted");
      refetch();
    },
  });

  const getCoverageColor = (pct: number) => {
    if (pct >= 80) return "bg-emerald-500";
    if (pct >= 60) return "bg-green-500";
    if (pct >= 40) return "bg-yellow-500";
    if (pct >= 20) return "bg-orange-500";
    return "bg-red-500";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6 text-violet-400" />
            Purple Team &amp; Detection Tests
          </h1>
          <p className="text-muted-foreground mt-1">
            Track red vs blue team results and identify detection gaps
          </p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              New Detection Test
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Detection Test</DialogTitle>
              <DialogDescription>Log a detection test result</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Technique ID</Label>
                  <Input value={newTechniqueId} onChange={(e) => setNewTechniqueId(e.target.value)} placeholder="T1059.001" />
                </div>
                <div>
                  <Label>Technique Name</Label>
                  <Input value={newTechniqueName} onChange={(e) => setNewTechniqueName(e.target.value)} placeholder="PowerShell" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Tactic</Label>
                  <Select value={newTactic} onValueChange={setNewTactic}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {TACTICS.map(t => (
                        <SelectItem key={t} value={t}>
                          {t.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Detected?</Label>
                  <Select value={newDetected ? "yes" : "no"} onValueChange={(v) => setNewDetected(v === "yes")}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="yes">Yes - Detected</SelectItem>
                      <SelectItem value="no">No - Gap</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div>
                <Label>Notes</Label>
                <Textarea value={newNotes} onChange={(e) => setNewNotes(e.target.value)} placeholder="Test details..." />
              </div>
            </div>
            <DialogFooter>
              <Button
                onClick={() => createMutation.mutate({
                  techniqueId: newTechniqueId,
                  techniqueName: newTechniqueName,
                  tactic: newTactic,
                  detected: newDetected,
                  isGap: !newDetected,
                  executionResult: "success",
                  notes: newNotes,
                })}
                disabled={!newTechniqueId || createMutation.isPending}
              >
                Create Test
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold">{stats?.totalTests ?? 0}</div>
            <div className="text-xs text-muted-foreground">Total Tests</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-emerald-400">{stats?.totalDetected ?? 0}</div>
            <div className="text-xs text-muted-foreground">Detected</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-red-400">{stats?.totalGaps ?? 0}</div>
            <div className="text-xs text-muted-foreground">Gaps</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-blue-400">{stats?.coverageRate ?? 0}%</div>
            <div className="text-xs text-muted-foreground">Coverage Rate</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-purple-400">{stats?.totalScores ?? 0}</div>
            <div className="text-xs text-muted-foreground">Defense Scores</div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b pb-2">
        {[
          { key: "tests", label: "Detection Tests", icon: Eye },
          { key: "matrix", label: "Coverage Matrix", icon: BarChart3 },
          { key: "scores", label: "Defense Scores", icon: Shield },
        ].map(tab => (
          <Button
            key={tab.key}
            variant={activeTab === tab.key ? "default" : "ghost"}
            size="sm"
            className="gap-2"
            onClick={() => setActiveTab(tab.key as any)}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </Button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === "tests" && (
        <>
          {/* Search & Filter */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Search techniques..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" />
            </div>
            <Select value={tacticFilter} onValueChange={setTacticFilter}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="All Tactics" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tactics</SelectItem>
                {TACTICS.map(t => (
                  <SelectItem key={t} value={t}>
                    {t.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={gapFilter} onValueChange={setGapFilter}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="All Results" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Results</SelectItem>
                <SelectItem value="detected">Detected</SelectItem>
                <SelectItem value="gaps">Gaps Only</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Test List */}
          <div className="space-y-3">
            {isLoading ? (
              <div className="text-center py-8 text-muted-foreground">Loading...</div>
            ) : !tests?.items?.length ? (
              <Card>
                <CardContent className="py-8 text-center text-muted-foreground">
                  <Eye className="h-10 w-10 mx-auto mb-3 opacity-40" />
                  <p>No detection tests yet</p>
                </CardContent>
              </Card>
            ) : (
              tests.items.map((test: any) => (
                <Card key={test.testId} className={`${test.isGap ? "border-red-500/30" : "border-emerald-500/30"}`}>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {test.detected ? (
                          <CheckCircle className="h-5 w-5 text-emerald-400" />
                        ) : (
                          <XCircle className="h-5 w-5 text-red-400" />
                        )}
                        <div>
                          <div className="flex items-center gap-2">
                            <code className="text-sm text-violet-400">{test.techniqueId}</code>
                            <span className="text-sm font-medium">{test.techniqueName}</span>
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            <Badge variant="outline" className="text-[10px] capitalize">
                              {test.tactic?.replace(/-/g, " ")}
                            </Badge>
                            {test.isGap && (
                              <Badge className="text-[10px] bg-red-500/20 text-red-400 border-red-500/30">
                                GAP
                              </Badge>
                            )}
                            {test.mitigationStatus && (
                              <Badge variant="outline" className="text-[10px]">
                                {test.mitigationStatus}
                              </Badge>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {test.isGap && test.mitigationStatus !== "resolved" && (
                          <Button
                            size="sm"
                            variant="outline"
                            className="text-xs"
                            onClick={() => updateMutation.mutate({
                              testId: test.testId,
                              mitigationStatus: "resolved",
                              detected: true,
                              isGap: false,
                            })}
                          >
                            Mark Resolved
                          </Button>
                        )}
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-8 w-8"
                          onClick={() => deleteMutation.mutate({ testId: test.testId })}
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                    {test.notes && (
                      <p className="text-xs text-muted-foreground mt-2 pl-8">{test.notes}</p>
                    )}
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </>
      )}

      {activeTab === "matrix" && matrix && (
        <Card>
          <CardHeader>
            <CardTitle>MITRE ATT&CK Detection Coverage Matrix</CardTitle>
            <CardDescription>
              Overall coverage: {matrix.summary.overallCoverage}% ({matrix.summary.totalDetected}/{matrix.summary.totalTests} detected)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {matrix.matrix.map((row: any) => (
                <div key={row.tactic} className="flex items-center gap-3">
                  <div className="w-40 text-sm capitalize truncate">
                    {row.tactic.replace(/-/g, " ")}
                  </div>
                  <div className="flex-1">
                    <div className="h-6 bg-zinc-800 rounded-full overflow-hidden relative">
                      <div
                        className={`h-full ${getCoverageColor(row.coverage)} transition-all rounded-full`}
                        style={{ width: `${Math.max(row.coverage, 2)}%` }}
                      />
                      <span className="absolute inset-0 flex items-center justify-center text-xs font-medium">
                        {row.coverage}%
                      </span>
                    </div>
                  </div>
                  <div className="w-24 text-xs text-right text-muted-foreground">
                    {row.detected}/{row.totalTests} detected
                  </div>
                  {row.gaps > 0 && (
                    <Badge className="text-[10px] bg-red-500/20 text-red-400">
                      {row.gaps} gaps
                    </Badge>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "scores" && (
        <div className="space-y-4">
          {!scores?.items?.length ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                <Shield className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p>No defense scores yet</p>
              </CardContent>
            </Card>
          ) : (
            scores.items.map((score: any) => (
              <Card key={score.scoreId}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="font-semibold">{score.organizationName}</h3>
                    <Badge className={`${
                      score.overallScore >= 70 ? "bg-emerald-500/20 text-emerald-400" :
                      score.overallScore >= 40 ? "bg-yellow-500/20 text-yellow-400" :
                      "bg-red-500/20 text-red-400"
                    }`}>
                      Score: {score.overallScore}
                    </Badge>
                  </div>
                  <div className="grid grid-cols-4 gap-4">
                    {[
                      { label: "Detection", value: score.detectionScore, color: "text-blue-400" },
                      { label: "Vulnerability", value: score.vulnerabilityScore, color: "text-orange-400" },
                      { label: "Surface", value: score.surfaceScore, color: "text-purple-400" },
                      { label: "Response", value: score.responseScore, color: "text-emerald-400" },
                    ].map(item => (
                      <div key={item.label} className="text-center">
                        <div className={`text-lg font-bold ${item.color}`}>{item.value}</div>
                        <div className="text-xs text-muted-foreground">{item.label}</div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      )}
    </div>
  );
}
