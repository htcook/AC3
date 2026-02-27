import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  PlayCircle,
  PlusCircle,
  Trash2,
  Terminal,
  Loader2,
  AlertCircle,
  ChevronRight,
  GitBranch,
  Github,
  Gitlab,
  Settings,
} from "lucide-react";
import AppShell from "@/components/AppShell";

const providerIcons: Record<string, React.ReactNode> = {
  custom: <Settings className="h-4 w-4" />,
  github_actions: <Github className="h-4 w-4" />,
  jenkins: <svg className="h-4 w-4" viewBox="0 0 24 24"><path fill="currentColor" d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm0 22C6.486 22 2 17.514 2 12S6.486 2 12 2s10 4.486 10 10-4.486 10-10 10zm-1-13.5c-.828 0-1.5.672-1.5 1.5s.672 1.5 1.5 1.5 1.5-.672 1.5-1.5-.672-1.5-1.5-1.5zm1.5 4.5h-3V18h3V13z"/></svg>,
  gitlab_ci: <Gitlab className="h-4 w-4" />,
  azure_devops: <svg className="h-4 w-4" viewBox="0 0 24 24"><path fill="currentColor" d="M18.2 0H5.8L.2 9.4l7.3 3.4-1.7 6.4 12.4-5.3-5.8-10.3zM8.3 10.3L3.7 2.9h10.8l3.5 6.2-9.7 1.2z"/></svg>,
};

const statusColors: Record<string, string> = {
  SUCCESS: "bg-green-500",
  FAILURE: "bg-red-500",
  PENDING: "bg-yellow-500",
  RUNNING: "bg-blue-500",
  CANCELLED: "bg-gray-500",
};

const CreatePipelineForm = ({ setOpen }: { setOpen: (v: boolean) => void }) => {
  const utils = trpc.useUtils();
  const [name, setName] = useState("");
  const [provider, setProvider] = useState<"github_actions" | "jenkins" | "gitlab_ci" | "azure_devops">("github_actions");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [triggerOn, setTriggerOn] = useState<"push" | "pull_request" | "release" | "manual">("push");

  const createPipeline = trpc.cicdPipeline.createPipeline.useMutation({
    onSuccess: () => {
      utils.cicdPipeline.listPipelines.invalidate();
      utils.cicdPipeline.getStats.invalidate();
      toast.success("Pipeline created successfully.");
      setOpen(false);
    },
    onError: (error: any) => {
      toast.error(`Failed to create pipeline: ${error.message}`);
    },
  });

  const handleSubmit = (e: any) => {
    e.preventDefault();
    if (!name || !webhookUrl) {
        toast.error("Pipeline name and webhook URL are required.");
        return;
    }
    createPipeline.mutate({ name, provider, webhookUrl, triggerOn });
  };

  return (
    <form onSubmit={handleSubmit} className="grid gap-4 py-4">
      <div className="grid grid-cols-4 items-center gap-4">
        <Label htmlFor="name" className="text-right">Name</Label>
        <Input id="name" value={name} onChange={(e) => setName(e.target.value)} className="col-span-3" placeholder="My Production Pipeline" />
      </div>
      <div className="grid grid-cols-4 items-center gap-4">
        <Label htmlFor="provider" className="text-right">Provider</Label>
        <Select onValueChange={(v) => setProvider(v as any)} defaultValue={provider}>
            <SelectTrigger className="col-span-3">
                <SelectValue placeholder="Select a provider" />
            </SelectTrigger>
            <SelectContent>
                <SelectItem value="github_actions">GitHub Actions</SelectItem>
                <SelectItem value="jenkins">Jenkins</SelectItem>
                <SelectItem value="gitlab_ci">GitLab CI</SelectItem>
                <SelectItem value="azure_devops">Azure DevOps</SelectItem>
            </SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-4 items-center gap-4">
        <Label htmlFor="webhookUrl" className="text-right">Webhook URL</Label>
        <Input id="webhookUrl" type="url" value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} className="col-span-3" placeholder="https://jenkins.example.com/..." />
      </div>
      <div className="grid grid-cols-4 items-center gap-4">
        <Label htmlFor="triggerOn" className="text-right">Trigger On</Label>
        <Select onValueChange={(v) => setTriggerOn(v as any)} defaultValue={triggerOn}>
            <SelectTrigger className="col-span-3">
                <SelectValue placeholder="Select a trigger" />
            </SelectTrigger>
            <SelectContent>
                <SelectItem value="push">Push</SelectItem>
                <SelectItem value="pull_request">Pull Request</SelectItem>
                <SelectItem value="release">Release</SelectItem>
                <SelectItem value="manual">Manual</SelectItem>
            </SelectContent>
        </Select>
      </div>
      <DialogFooter>
        <Button type="submit" disabled={createPipeline.isPending}>
          {createPipeline.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Create Pipeline
        </Button>
      </DialogFooter>
    </form>
  );
};

export default function CicdPipelinePage() {
  const [isCreateOpen, setCreateOpen] = useState(false);
  const [selectedPipelineId, setSelectedPipelineId] = useState<number | null>(null);

  const statsQuery = trpc.cicdPipeline.getStats.useQuery();
  const pipelinesQuery = trpc.cicdPipeline.listPipelines.useQuery();
  const runsQuery = trpc.cicdPipeline.listRuns.useQuery({ pipelineId: selectedPipelineId || undefined } as any, { enabled: !!selectedPipelineId });

  const utils = trpc.useUtils();

  const deletePipeline = trpc.cicdPipeline.deletePipeline.useMutation({
    onSuccess: () => {
      utils.cicdPipeline.listPipelines.invalidate();
      utils.cicdPipeline.getStats.invalidate();
      toast.success("Pipeline deleted.");
    },
    onError: (error: any) => toast.error(`Deletion failed: ${error.message}`),
  });

  const triggerRun = trpc.cicdPipeline.triggerRun.useMutation({
    onSuccess: () => {
        utils.cicdPipeline.listRuns.invalidate();
        utils.cicdPipeline.getStats.invalidate();
        toast.success("Pipeline run triggered.");
    },
    onError: (error: any) => toast.error(`Trigger failed: ${error.message}`),
  });

  const stats = useMemo(() => statsQuery.data, [statsQuery.data]);

  return (
    <AppShell activePath="/cicd-pipeline">
      <div className="min-h-screen bg-background text-foreground p-4 sm:p-6 lg:p-8">
      <div className="max-w-7xl mx-auto space-y-6">
        <header>
          <h1 className="text-3xl font-bold tracking-tight">CI/CD Pipelines</h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Configure and monitor automated security testing pipelines that run on schedule or trigger from events. Set up continuous validation workflows that automatically test your defenses — running emulation plans, scanning for new vulnerabilities, and verifying remediation. View pipeline run history, check for failures, and drill into individual test results.</p>
          <p className="text-muted-foreground mt-1">Manage CI/CD pipelines, trigger validation runs, and view history.</p>
        </header>

        {statsQuery.isLoading ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {[...Array(4)].map((_, i) => <Card key={i} className="animate-pulse"><CardHeader><div className="h-6 bg-muted rounded w-3/4"></div></CardHeader><CardContent><div className="h-8 bg-muted rounded w-1/2"></div></CardContent></Card>)}
            </div>
        ) : statsQuery.isError ? (
            <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>Could not load CI/CD statistics. {statsQuery.error.message}</AlertDescription>
            </Alert>
        ) : stats && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader><CardTitle>Total Pipelines</CardTitle></CardHeader>
              <CardContent><p className="text-2xl font-bold">{stats.totalPipelines}</p></CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle>Total Runs</CardTitle></CardHeader>
              <CardContent><p className="text-2xl font-bold">{stats.totalRuns}</p></CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle>Pass Rate</CardTitle></CardHeader>
              <CardContent><p className="text-2xl font-bold">N/A</p></CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle>Avg. Duration</CardTitle></CardHeader>
              <CardContent><p className="text-2xl font-bold">N/A</p></CardContent>
            </Card>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                    <div>
                        <CardTitle>Pipelines</CardTitle>
                        <CardDescription>CI/CD pipelines integrated with Ace C3.</CardDescription>
                    </div>
                    <Dialog open={isCreateOpen} onOpenChange={setCreateOpen}>
                        <DialogTrigger asChild>
                            <Button size="sm"><PlusCircle className="mr-2 h-4 w-4" /> Add Pipeline</Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-[425px]">
                            <DialogHeader>
                                <DialogTitle>Create New Pipeline</DialogTitle>
                                <DialogDescription>Configure a new CI/CD pipeline to integrate with the system.</DialogDescription>
                            </DialogHeader>
                            <CreatePipelineForm setOpen={setCreateOpen} />
                        </DialogContent>
                    </Dialog>
                </CardHeader>
                <CardContent>
                    {pipelinesQuery.isLoading ? (
                        <div className="flex items-center justify-center p-10"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
                    ) : pipelinesQuery.isError ? (
                        <Alert variant="destructive">
                            <AlertCircle className="h-4 w-4" />
                            <AlertTitle>Error Loading Pipelines</AlertTitle>
                            <AlertDescription>{pipelinesQuery.error.message}</AlertDescription>
                        </Alert>
                    ) : (pipelinesQuery.data?.length ?? 0) === 0 ? (
                        <div className="text-center text-muted-foreground py-10">No pipelines configured yet.</div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Name</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Trigger</TableHead>
                                    <TableHead className="text-right">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {pipelinesQuery.data?.map((p) => (
                                    <TableRow key={p.id} className={`cursor-pointer ${selectedPipelineId === p.id ? 'bg-muted/50' : ''}`} onClick={() => setSelectedPipelineId(p.id)}>
                                        <TableCell className="font-medium flex items-center gap-2">
                                            {providerIcons[p.provider]} {p.name}
                                        </TableCell>
                                        <TableCell><Badge variant={p.isActive ? "default" : "outline"}>{p.isActive ? "Active" : "Inactive"}</Badge></TableCell>
                                        <TableCell className="capitalize">{p.triggerOn.replace('_', ' ')}</TableCell>
                                        <TableCell className="text-right space-x-2">
                                            <Button size="icon" variant="ghost" onClick={(e) => { e.stopPropagation(); triggerRun.mutate({ pipelineId: p.id }); }} disabled={triggerRun.isPending}><PlayCircle className="h-4 w-4" /></Button>
                                            <Button size="icon" variant="ghost" className="text-destructive" onClick={(e) => { e.stopPropagation(); deletePipeline.mutate({ id: p.id }); }} disabled={deletePipeline.isPending}><Trash2 className="h-4 w-4" /></Button>
                                            <Button size="icon" variant="ghost" onClick={() => setSelectedPipelineId(p.id)}><ChevronRight className="h-4 w-4" /></Button>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <CardTitle>Recent Runs</CardTitle>
                    <CardDescription>History of recent pipeline executions.</CardDescription>
                </CardHeader>
                <CardContent>
                    {!selectedPipelineId ? (
                        <div className="text-center text-muted-foreground py-10">Select a pipeline to view its runs.</div>
                    ) : runsQuery.isLoading ? (
                        <div className="flex items-center justify-center p-10"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
                    ) : runsQuery.isError ? (
                        <Alert variant="destructive">
                            <AlertCircle className="h-4 w-4" />
                            <AlertTitle>Error Loading Runs</AlertTitle>
                            <AlertDescription>{runsQuery.error.message}</AlertDescription>
                        </Alert>
                    ) : (runsQuery.data?.length ?? 0) === 0 ? (
                        <div className="text-center text-muted-foreground py-10">No runs found for this pipeline.</div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Run</TableHead>
                                    <TableHead>Commit</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead className="text-right">Completed</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {runsQuery.data?.map((run) => (
                                    <TableRow key={run.id}>
                                        <TableCell className="font-medium flex items-center gap-2">
                                            <GitBranch className="h-4 w-4" /> {run.branch}
                                        </TableCell>
                                        <TableCell className="font-mono text-xs">{run.commitSha?.substring(0, 7)}</TableCell>
                                        <TableCell>
                                            <div className="flex items-center gap-2">
                                                <span className={`h-2 w-2 rounded-full ${(statusColors as any)[run.status] || 'bg-gray-400'}`} />
                                                <span className="capitalize">{run.status.toLowerCase()}</span>
                                            </div>
                                        </TableCell>
                                        <TableCell className="text-right text-muted-foreground text-xs">{new Date(run.completedAt || run.createdAt).toLocaleString()}</TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>
        </div>
      </div>
    </div>
    </AppShell>
  );
}
