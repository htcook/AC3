import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { PlusCircle, Edit, Trash2, Play, Loader2, AlertCircle, GitBranch, ChevronsRight } from "lucide-react";

const pipelineProviders = ["github_actions", "jenkins", "gitlab_ci", "azure_devops", "custom"];
const triggerOptions = ["push", "pull_request", "release", "manual", "schedule"];

type Pipeline = {
  id: string;
  name: string;
  provider: string;
  isActive: boolean;
  triggerOn: string[];
  failThreshold: number | null;
  webhookUrl: string | null;
};

export default function CicdPipeline() {
  const [isCreateDialogOpen, setCreateDialogOpen] = useState(false);
  const [isEditDialogOpen, setEditDialogOpen] = useState(false);
  const [selectedPipeline, setSelectedPipeline] = useState<Pipeline | null>(null);
  const [activeTab, setActiveTab] = useState("pipelines");

  const utils = trpc.useUtils();

  const { data: pipelines, isLoading: isLoadingPipelines, error: pipelinesError } = trpc.cicdPipeline.listPipelines.useQuery();
  const { data: stats, isLoading: isLoadingStats } = trpc.cicdPipeline.getStats.useQuery();
  const { data: runs, isLoading: isLoadingRuns } = trpc.cicdPipeline.listRuns.useQuery(
    { pipelineId: selectedPipeline?.id },
    { enabled: !!selectedPipeline }
  );

  const createPipelineMutation = trpc.cicdPipeline.createPipeline.useMutation({
    onSuccess: () => {
      utils.cicdPipeline.listPipelines.invalidate();
      utils.cicdPipeline.getStats.invalidate();
      toast.success("Pipeline created successfully.");
      setCreateDialogOpen(false);
    },
    onError: (error) => {
      toast.error(`Failed to create pipeline: ${error.message}`);
    },
  });

  const updatePipelineMutation = trpc.cicdPipeline.updatePipeline.useMutation({
    onSuccess: () => {
      utils.cicdPipeline.listPipelines.invalidate();
      toast.success("Pipeline updated successfully.");
      setEditDialogOpen(false);
    },
    onError: (error) => {
      toast.error(`Failed to update pipeline: ${error.message}`);
    },
  });

  const deletePipelineMutation = trpc.cicdPipeline.deletePipeline.useMutation({
    onSuccess: () => {
      utils.cicdPipeline.listPipelines.invalidate();
      utils.cicdPipeline.getStats.invalidate();
      toast.success("Pipeline deleted successfully.");
    },
    onError: (error) => {
      toast.error(`Failed to delete pipeline: ${error.message}`);
    },
  });

  const triggerRunMutation = trpc.cicdPipeline.triggerRun.useMutation({
    onSuccess: () => {
      utils.cicdPipeline.listRuns.invalidate({ pipelineId: selectedPipeline?.id });
      toast.success("Pipeline run triggered.");
    },
    onError: (error) => {
      toast.error(`Failed to trigger run: ${error.message}`);
    },
  });

  const handleEditClick = (pipeline: Pipeline) => {
    setSelectedPipeline(pipeline);
    setEditDialogOpen(true);
  };

  const handleDeleteClick = (id: string) => {
    if (window.confirm("Are you sure you want to delete this pipeline?")) {
      deletePipelineMutation.mutate({ id });
    }
  };

  const handleTriggerRun = (pipelineId: string) => {
    triggerRunMutation.mutate({ pipelineId });
  };

  const PipelineForm = ({ pipeline, isEdit = false }: { pipeline?: Pipeline | null, isEdit?: boolean }) => {
    const [name, setName] = useState(pipeline?.name || "");
    const [provider, setProvider] = useState(pipeline?.provider || "");
    const [webhookUrl, setWebhookUrl] = useState(pipeline?.webhookUrl || "");
    const [triggerOn, setTriggerOn] = useState<string[]>(pipeline?.triggerOn || []);
    const [failThreshold, setFailThreshold] = useState(pipeline?.failThreshold?.toString() || "");

    const handleSubmit = (e: React.FormEvent) => {
      e.preventDefault();
      const mutation = isEdit ? updatePipelineMutation : createPipelineMutation;
      const payload = {
        ...(isEdit && pipeline && { id: pipeline.id }),
        name,
        provider,
        webhookUrl: webhookUrl || undefined,
        triggerOn,
        failThreshold: failThreshold ? parseInt(failThreshold, 10) : undefined,
      };
      // @ts-ignore
      mutation.mutate(payload);
    };

    return (
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid gap-2">
          <Label htmlFor="name">Pipeline Name</Label>
          <Input id="name" value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="provider">Provider</Label>
          <Select value={provider} onValueChange={setProvider} required>
            <SelectTrigger id="provider">
              <SelectValue placeholder="Select a provider" />
            </SelectTrigger>
            <SelectContent>
              {pipelineProviders.map(p => <SelectItem key={p} value={p}>{p}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="webhookUrl">Webhook URL (Optional)</Label>
          <Input id="webhookUrl" value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} />
        </div>
        <div className="grid gap-2">
          <Label>Trigger On</Label>
          <div className="flex flex-wrap gap-2">
            {triggerOptions.map(opt => (
              <Button
                key={opt}
                type="button"
                variant={triggerOn.includes(opt) ? "secondary" : "outline"}
                onClick={() => {
                  setTriggerOn(prev => 
                    prev.includes(opt) ? prev.filter(p => p !== opt) : [...prev, opt]
                  );
                }}
              >
                {opt}
              </Button>
            ))}
          </div>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="failThreshold">Fail Threshold (Optional)</Label>
          <Input id="failThreshold" type="number" value={failThreshold} onChange={(e) => setFailThreshold(e.target.value)} placeholder="e.g., 80" />
        </div>
        <DialogFooter>
          <Button type="submit" disabled={createPipelineMutation.isPending || updatePipelineMutation.isPending}>
            {createPipelineMutation.isPending || updatePipelineMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            {isEdit ? "Save Changes" : "Create Pipeline"}
          </Button>
        </DialogFooter>
      </form>
    );
  };

  const statCards = useMemo(() => {
    if (isLoadingStats || !stats) {
      return Array(4).fill(0).map((_, i) => (
        <Card key={i} className="bg-slate-800/50 animate-pulse">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-slate-400 h-5 bg-slate-700 rounded"></CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold h-8 bg-slate-700 rounded"></div>
          </CardContent>
        </Card>
      ));
    }
    return [
      { title: "Total Pipelines", value: stats.totalPipelines },
      { title: "Active Pipelines", value: stats.activePipelines },
      { title: "Total Runs (24h)", value: stats.runsToday },
      { title: "Failed Runs (24h)", value: stats.failedRunsToday, color: "text-red-500" },
    ].map(stat => (
      <Card key={stat.title} className="bg-slate-800/50">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-slate-400">{stat.title}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className={`text-2xl font-bold ${stat.color || ''}`}>{stat.value}</div>
        </CardContent>
      </Card>
    ));
  }, [stats, isLoadingStats]);

  return (
    <div className="min-h-screen bg-slate-900 text-white p-8">
      <Card className="mb-8 bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle>CI/CD Security Pipelines</CardTitle>
          <CardDescription className="text-slate-400">
            Integrate security validation into your CI/CD pipelines. Connect to providers like GitHub Actions, Jenkins, and more to automate security checks on every deployment.
          </CardDescription>
        </CardHeader>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-8">
        {statCards}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <div className="flex justify-between items-center mb-4">
          <TabsList>
            <TabsTrigger value="pipelines">Pipelines</TabsTrigger>
            <TabsTrigger value="runs" disabled={!selectedPipeline}>Run History</TabsTrigger>
          </TabsList>
          {activeTab === "pipelines" && (
            <Dialog open={isCreateDialogOpen} onOpenChange={setCreateDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <PlusCircle className="mr-2 h-4 w-4" /> Create Pipeline
                </Button>
              </DialogTrigger>
              <DialogContent className="sm:max-w-[425px] bg-slate-900 border-slate-700">
                <DialogHeader>
                  <DialogTitle>Create New Pipeline</DialogTitle>
                  <DialogDescription>Configure a new CI/CD security pipeline.</DialogDescription>
                </DialogHeader>
                <PipelineForm />
              </DialogContent>
            </Dialog>
          )}
        </div>
        <TabsContent value="pipelines">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700 hover:bg-slate-800/60">
                    <TableHead>Name</TableHead>
                    <TableHead>Provider</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Triggers</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {isLoadingPipelines ? (
                    <TableRow><TableCell colSpan={5} className="text-center"><Loader2 className="mx-auto h-8 w-8 animate-spin text-slate-400" /></TableCell></TableRow>
                  ) : pipelinesError ? (
                    <TableRow><TableCell colSpan={5} className="text-center text-red-500"><AlertCircle className="inline-block mr-2" /> Error: {pipelinesError.message}</TableCell></TableRow>
                  ) : pipelines && pipelines.length > 0 ? (
                    pipelines.map((pipeline) => (
                      <TableRow key={pipeline.id} className="border-slate-700 hover:bg-slate-800/60 cursor-pointer" onClick={() => { setSelectedPipeline(pipeline); setActiveTab("runs"); }}>
                        <TableCell className="font-medium">{pipeline.name}</TableCell>
                        <TableCell>{pipeline.provider}</TableCell>
                        <TableCell><Badge variant={pipeline.isActive ? "default" : "destructive"}>{pipeline.isActive ? "Active" : "Inactive"}</Badge></TableCell>
                        <TableCell className="space-x-1">{pipeline.triggerOn.map(t => <Badge key={t} variant="outline">{t}</Badge>)}</TableCell>
                        <TableCell className="text-right space-x-2">
                          <Button variant="ghost" size="icon" onClick={(e) => { e.stopPropagation(); handleTriggerRun(pipeline.id); }} disabled={triggerRunMutation.isPending}><Play className="h-4 w-4" /></Button>
                          <Button variant="ghost" size="icon" onClick={(e) => { e.stopPropagation(); handleEditClick(pipeline); }}><Edit className="h-4 w-4" /></Button>
                          <Button variant="ghost" size="icon" onClick={(e) => { e.stopPropagation(); handleDeleteClick(pipeline.id); }} disabled={deletePipelineMutation.isPending}><Trash2 className="h-4 w-4 text-red-500" /></Button>
                        </TableCell>
                      </TableRow>
                    ))
                  ) : (
                    <TableRow><TableCell colSpan={5} className="text-center text-slate-400">No pipelines configured yet.</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="runs">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle>Run History for {selectedPipeline?.name}</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
            <Table>
                <TableHeader>
                  <TableRow className="border-slate-700 hover:bg-slate-800/60">
                    <TableHead>Run ID</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Commit SHA</TableHead>
                    <TableHead>Branch</TableHead>
                    <TableHead>Triggered At</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {isLoadingRuns ? (
                    <TableRow><TableCell colSpan={5} className="text-center"><Loader2 className="mx-auto h-8 w-8 animate-spin text-slate-400" /></TableCell></TableRow>
                  ) : runs && runs.length > 0 ? (
                    runs.map((run: any) => (
                      <TableRow key={run.id} className="border-slate-700 hover:bg-slate-800/60">
                        <TableCell className="font-mono text-xs">{run.id}</TableCell>
                        <TableCell><Badge variant={run.status === 'success' ? 'success' : 'destructive'}>{run.status}</Badge></TableCell>
                        <TableCell className="font-mono text-xs">{run.commitSha}</TableCell>
                        <TableCell><GitBranch className="inline-block mr-2 h-4 w-4" />{run.branch}</TableCell>
                        <TableCell>{new Date(run.triggeredAt).toLocaleString()}</TableCell>
                      </TableRow>
                    ))
                  ) : (
                    <TableRow><TableCell colSpan={5} className="text-center text-slate-400">No runs found for this pipeline.</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Dialog open={isEditDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="sm:max-w-[425px] bg-slate-900 border-slate-700">
          <DialogHeader>
            <DialogTitle>Edit Pipeline</DialogTitle>
            <DialogDescription>Update the configuration for {selectedPipeline?.name}.</DialogDescription>
          </DialogHeader>
          <PipelineForm pipeline={selectedPipeline} isEdit />
        </DialogContent>
      </Dialog>
    </div>
  );
}
