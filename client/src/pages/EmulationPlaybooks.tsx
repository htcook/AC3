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
  Play, Plus, Search, BookOpen, Zap, Clock, Target,
  ChevronDown, ChevronRight, Trash2, Edit, Rocket, Shield
} from "lucide-react";
import ROEWarningBanner from "@/components/ROEWarningBanner";
import AppShell from "@/components/AppShell";

function AdversaryProfileCard({ profile: raw }: { profile: unknown }) {
  if (!raw) return null;
  const profile: any = typeof raw === "string" ? JSON.parse(raw) : raw;
  return (
    <div className="rounded-lg border p-4 bg-zinc-900/50">
      <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
        <Shield className="h-4 w-4 text-red-400" />
        Adversary Profile
      </h4>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-sm">
        <div><span className="text-muted-foreground">Actor:</span> {profile.actorName}</div>
        <div><span className="text-muted-foreground">Origin:</span> {profile.origin || "Unknown"}</div>
        <div><span className="text-muted-foreground">Sophistication:</span> {profile.sophistication || "Unknown"}</div>
        <div><span className="text-muted-foreground">Motivation:</span> {profile.motivation || "Unknown"}</div>
        <div><span className="text-muted-foreground">TTPs:</span> {profile.ttpCount}</div>
        <div><span className="text-muted-foreground">Phases:</span> {profile.phaseCount}</div>
      </div>
    </div>
  );
}

export default function EmulationPlaybooks() {
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showGenerateDialog, setShowGenerateDialog] = useState(false);
  const [selectedPlaybook, setSelectedPlaybook] = useState<string | null>(null);
  const [expandedPhases, setExpandedPhases] = useState<Set<number>>(new Set());

  // Form state
  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newDifficulty, setNewDifficulty] = useState("intermediate");
  const [selectedActorId, setSelectedActorId] = useState<number | null>(null);

  const searchInput = useMemo(() => ({ search: search || undefined, status: statusFilter || undefined }), [search, statusFilter]);
  const { data: playbooks, isLoading, refetch } = trpc.emulationPlaybooks.list.useQuery(searchInput);
  const { data: stats } = trpc.emulationPlaybooks.stats.useQuery();
  const { data: selectedPb } = trpc.emulationPlaybooks.get.useQuery(
    { playbookId: selectedPlaybook! },
    { enabled: !!selectedPlaybook }
  );

  // Get threat actors for generation
  const { data: actors } = trpc.threatIntel.list.useQuery(
    { page: 1, pageSize: 50 },
    { enabled: showGenerateDialog }
  );

  const createMutation = trpc.emulationPlaybooks.create.useMutation({
    onSuccess: () => {
      toast.success("Playbook created successfully");
      setShowCreateDialog(false);
      setNewName("");
      setNewDescription("");
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const generateMutation = trpc.emulationPlaybooks.generateFromActor.useMutation({
    onSuccess: (data) => {
      toast.success(`Generated "${data.name}" with ${data.techniques} techniques across ${data.phases} phases`);
      setShowGenerateDialog(false);
      setSelectedActorId(null);
      refetch();
    },
    onError: (err) => toast.error(`Generation failed: ${sanitizeErrorForToast(err)}`),
  });

  const launchMutation = trpc.emulationPlaybooks.launch.useMutation({
    onSuccess: (data) => {
      toast.success(data.operationId
        ? `Operation ${data.operationId} started`
        : "Execution queued (emulation framework connection pending)");
      refetch();
    },
    onError: (err) => toast.error(`Launch failed: ${sanitizeErrorForToast(err)}`),
  });

  const deleteMutation = trpc.emulationPlaybooks.delete.useMutation({
    onSuccess: () => {
      toast.success("Playbook removed");
      setSelectedPlaybook(null);
      refetch();
    },
  });

  const togglePhase = (idx: number) => {
    setExpandedPhases(prev => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  };

  const getDifficultyColor = (d: string | null) => {
    switch (d) {
      case "beginner": return "bg-green-500/20 text-green-400 border-green-500/30";
      case "intermediate": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
      case "advanced": return "bg-red-500/20 text-red-400 border-red-500/30";
      default: return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
    }
  };

  const getStatusColor = (s: string) => {
    switch (s) {
      case "active": return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
      case "draft": return "bg-blue-500/20 text-blue-400 border-blue-500/30";
      case "archived": return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
      default: return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
    }
  };

  return (
    <AppShell activePath="/emulation-playbooks">
      <div className="space-y-6">
      {/* ROE Warning Banner */}
      <ROEWarningBanner riskTier="red" operationName="Adversary Emulation" />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <BookOpen className="h-6 w-6 text-orange-400" />
            Adversary Emulation Playbooks
          </h1>
          <p className="text-muted-foreground mt-1">
            Map threat actor TTPs to adversary operations for one-click adversary emulation
          </p>
        </div>
        <div className="flex gap-2">
          <Dialog open={showGenerateDialog} onOpenChange={setShowGenerateDialog}>
            <DialogTrigger asChild>
              <Button variant="outline" className="gap-2">
                <Zap className="h-4 w-4" />
                Generate from Actor
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Generate Playbook from Threat Actor</DialogTitle>
                <DialogDescription>
                  Select a threat actor to automatically generate an emulation playbook from their known TTPs
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div>
                  <Label>Threat Actor</Label>
                  <Select onValueChange={(v) => setSelectedActorId(Number(v))}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select a threat actor..." />
                    </SelectTrigger>
                    <SelectContent>
                      {(actors as any)?.actors?.map((a: any) => (
                        <SelectItem key={a.id} value={String(a.id)}>
                          {a.name} ({a.type})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <Button
                  onClick={() => selectedActorId && generateMutation.mutate({ threatActorId: selectedActorId })}
                  disabled={!selectedActorId || generateMutation.isPending}
                  className="gap-2"
                >
                  <Zap className="h-4 w-4" />
                  {generateMutation.isPending ? "Generating..." : "Generate Playbook"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
            <DialogTrigger asChild>
              <Button className="gap-2">
                <Plus className="h-4 w-4" />
                Create Playbook
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create Manual Playbook</DialogTitle>
                <DialogDescription>Create a custom emulation playbook</DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div>
                  <Label>Name</Label>
                  <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Playbook name..." />
                </div>
                <div>
                  <Label>Description</Label>
                  <Textarea value={newDescription} onChange={(e) => setNewDescription(e.target.value)} placeholder="Describe the playbook..." />
                </div>
                <div>
                  <Label>Difficulty</Label>
                  <Select value={newDifficulty} onValueChange={setNewDifficulty}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="beginner">Beginner</SelectItem>
                      <SelectItem value="intermediate">Intermediate</SelectItem>
                      <SelectItem value="advanced">Advanced</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <Button
                  onClick={() => createMutation.mutate({ name: newName, description: newDescription, difficulty: newDifficulty })}
                  disabled={!newName || createMutation.isPending}
                >
                  Create
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold">{stats?.totalPlaybooks ?? 0}</div>
            <div className="text-xs text-muted-foreground">Total Playbooks</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-emerald-400">{stats?.activePlaybooks ?? 0}</div>
            <div className="text-xs text-muted-foreground">Active</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-blue-400">{stats?.draftPlaybooks ?? 0}</div>
            <div className="text-xs text-muted-foreground">Drafts</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-purple-400">{stats?.totalExecutions ?? 0}</div>
            <div className="text-xs text-muted-foreground">Executions</div>
          </CardContent>
        </Card>
      </div>

      {/* Search & Filter */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search playbooks..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="All Statuses" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="draft">Draft</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="archived">Archived</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Playbook List + Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* List */}
        <div className="lg:col-span-1 space-y-3">
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading playbooks...</div>
          ) : !playbooks?.items?.length ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                <BookOpen className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p>No playbooks yet</p>
                <p className="text-sm mt-1">Generate one from a threat actor or create manually</p>
              </CardContent>
            </Card>
          ) : (
            playbooks.items.map((pb: any) => (
              <Card
                key={pb.playbookId}
                className={`cursor-pointer transition-colors hover:border-orange-500/50 ${
                  selectedPlaybook === pb.playbookId ? "border-orange-500" : ""
                }`}
                onClick={() => setSelectedPlaybook(pb.playbookId)}
              >
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-sm truncate">{pb.name}</h3>
                      {pb.threatActorName && (
                        <div className="flex items-center gap-1 mt-1">
                          <Target className="h-3 w-3 text-red-400" />
                          <span className="text-xs text-red-400">{pb.threatActorName}</span>
                        </div>
                      )}
                    </div>
                    <Badge className={`text-[10px] ${getStatusColor(pb.status)}`}>{pb.status}</Badge>
                  </div>
                  <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                    {pb.difficulty && (
                      <Badge variant="outline" className={`text-[10px] ${getDifficultyColor(pb.difficulty)}`}>
                        {pb.difficulty}
                      </Badge>
                    )}
                    {pb.estimatedDuration && (
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />{pb.estimatedDuration}m
                      </span>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>

        {/* Detail Panel */}
        <div className="lg:col-span-2">
          {selectedPb ? (
            <Card>
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <BookOpen className="h-5 w-5 text-orange-400" />
                      {selectedPb.name}
                    </CardTitle>
                    <CardDescription className="mt-1">{selectedPb.description}</CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      className="gap-1 bg-orange-600 hover:bg-orange-700"
                      onClick={() => launchMutation.mutate({ playbookId: selectedPb.playbookId })}
                      disabled={launchMutation.isPending}
                    >
                      <Rocket className="h-3 w-3" />
                      {launchMutation.isPending ? "Launching..." : "Launch"}
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => deleteMutation.mutate({ playbookId: selectedPb.playbookId })}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Adversary Profile */}
                {selectedPb.actorName && (
                  <div className="rounded-lg border border-border/50 bg-zinc-900/50 p-3">
                    <h4 className="text-sm font-semibold mb-2">Threat Actor</h4>
                    <p className="text-sm text-amber-400">{selectedPb.actorName}</p>
                  </div>
                )}

                {/* Kill Chain Phases */}
                <div>
                  <h4 className="text-sm font-semibold mb-3">Kill Chain Phases</h4>
                  {(() => {
                    const phases = typeof selectedPb.phases === "string"
                      ? JSON.parse(selectedPb.phases)
                      : selectedPb.phases;
                    if (!Array.isArray(phases) || phases.length === 0) {
                      return <p className="text-sm text-muted-foreground">No phases defined</p>;
                    }
                    return (
                      <div className="space-y-2">
                        {phases.map((phase: any, idx: number) => (
                          <div key={idx} className="border rounded-lg">
                            <button
                              className="w-full flex items-center justify-between p-3 text-left hover:bg-zinc-800/50"
                              onClick={() => togglePhase(idx)}
                            >
                              <div className="flex items-center gap-2">
                                {expandedPhases.has(idx) ? (
                                  <ChevronDown className="h-4 w-4" />
                                ) : (
                                  <ChevronRight className="h-4 w-4" />
                                )}
                                <Badge variant="outline" className="text-[10px]">Phase {phase.order || idx + 1}</Badge>
                                <span className="text-sm font-medium capitalize">{phase.tactic?.replace(/-/g, " ")}</span>
                              </div>
                              <span className="text-xs text-muted-foreground">
                        {String(phase.techniques?.length || 0)} techniques
                      </span>
                            </button>
                            {expandedPhases.has(idx) && (
                              <div className="px-3 pb-3 space-y-1">
                                {phase.techniques?.map((tech: any, tIdx: number) => (
                                  <div key={tIdx} className="flex items-center gap-2 text-sm py-1 px-2 rounded bg-zinc-800/30">
                                    <code className="text-orange-400 text-xs">{tech.techniqueId}</code>
                                    <span className="text-muted-foreground">{tech.techniqueName}</span>
                                    {tech.abilityId && (
                                      <Badge variant="outline" className="text-[9px] ml-auto">
                                        Ability: {tech.abilityId.slice(0, 8)}...
                                      </Badge>
                                    )}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    );
                  })()}
                </div>

                {/* Metadata */}
                <div className="flex flex-wrap gap-2 pt-2 border-t text-xs text-muted-foreground">
                  <span>Created: {new Date(selectedPb.createdAt).toLocaleDateString()}</span>
                  {selectedPb.calderaAdversaryId && (
                    <span>emulation framework Adversary: {selectedPb.calderaAdversaryId}</span>
                  )}
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="py-16 text-center text-muted-foreground">
                <BookOpen className="h-12 w-12 mx-auto mb-4 opacity-30" />
                <p className="text-lg">Select a playbook to view details</p>
                <p className="text-sm mt-1">Or generate one from a threat actor's TTPs</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
    </AppShell>
  );
}
