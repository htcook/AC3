import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { FileText, Bot, ShieldCheck, Trash2, Loader2, PlusCircle, AlertTriangle, Cpu, History } from "lucide-react";

type PlanStatus = "generating" | "completed" | "ready" | "executing";

const statusConfig: Record<PlanStatus, { color: string; icon: React.ElementType }> = {
  generating: { color: "bg-blue-500", icon: Loader2 },
  completed: { color: "bg-green-500", icon: ShieldCheck },
  ready: { color: "bg-yellow-500", icon: FileText },
  executing: { color: "bg-purple-500", icon: Cpu },
};

export default function AiAttackPlanner() {
  const [statusFilter, setStatusFilter] = useState<PlanStatus | "all">("all");
  const [selectedPlanId, setSelectedPlanId] = useState<string | null>(null);
  const [isGenerateDialogOpen, setGenerateDialogOpen] = useState(false);

  const utils = trpc.useUtils();

  const statsQuery = trpc.aiAttackPlanner.getStats.useQuery();
  const plansQuery = trpc.aiAttackPlanner.list.useQuery(
    statusFilter === "all" ? {} : { status: [statusFilter] },
    { refetchInterval: 5000 } // Poll for updates on generating plans
  );
  const profilesQuery = trpc.aiAttackPlanner.listThreatActorProfiles.useQuery();

  const selectedPlanQuery = trpc.aiAttackPlanner.get.useQuery(
    { id: selectedPlanId! },
    { enabled: !!selectedPlanId, refetchOnWindowFocus: false }
  );

  const generateMutation = trpc.aiAttackPlanner.generate.useMutation({
    onSuccess: (data) => {
      toast.success(`Attack plan "${data.name}" is being generated.`);
      utils.aiAttackPlanner.list.invalidate();
      utils.aiAttackPlanner.getStats.invalidate();
      setGenerateDialogOpen(false);
    },
    onError: (error) => {
      toast.error("Failed to generate plan: " + error.message);
    },
  });

  const acceptMutation = trpc.aiAttackPlanner.accept.useMutation({
    onSuccess: (data) => {
      toast.success(`Plan "${data.name}" accepted and is now executing.`);
      utils.aiAttackPlanner.list.invalidate();
      utils.aiAttackPlanner.get.invalidate({ id: data.id });
      utils.aiAttackPlanner.getStats.invalidate();
    },
    onError: (error) => toast.error("Failed to accept plan: " + error.message),
  });

  const deleteMutation = trpc.aiAttackPlanner.delete.useMutation({
    onSuccess: (_, variables) => {
      toast.info("Plan deleted.");
      utils.aiAttackPlanner.list.invalidate();
      utils.aiAttackPlanner.getStats.invalidate();
      if (selectedPlanId === variables.id) {
        setSelectedPlanId(null);
      }
    },
    onError: (error) => toast.error("Failed to delete plan: " + error.message),
  });

  const handleGeneratePlan = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const data = Object.fromEntries(formData.entries()) as { name: string; targetDescription: string; threatActorProfile: string };
    generateMutation.mutate(data);
  };

  const stats = useMemo(() => statsQuery.data ?? { generating: 0, completed: 0, ready: 0, executing: 0 }, [statsQuery.data]);

  const renderStatCards = () => (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Ready to Execute</CardTitle>
          <FileText className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{stats.ready}</div>
          <p className="text-xs text-muted-foreground">Plans awaiting approval</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Executing</CardTitle>
          <Cpu className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{stats.executing}</div>
          <p className="text-xs text-muted-foreground">Active attack simulations</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Completed</CardTitle>
          <ShieldCheck className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{stats.completed}</div>
          <p className="text-xs text-muted-foreground">Finished simulations</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Generating</CardTitle>
          <Bot className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{stats.generating}</div>
          <p className="text-xs text-muted-foreground">AI is currently creating plans</p>
        </CardContent>
      </Card>
    </div>
  );

  const renderPlanList = () => {
    if (plansQuery.isLoading) {
      return <div className="flex justify-center items-center p-8"><Loader2 className="h-8 w-8 animate-spin" /></div>;
    }
    if (plansQuery.isError) {
      return <div className="text-red-500 text-center p-8">Error loading plans: {plansQuery.error.message}</div>;
    }
    if (!plansQuery.data || plansQuery.data.length === 0) {
      return (
        <div className="text-center py-12">
          <FileText className="mx-auto h-12 w-12 text-muted-foreground" />
          <h3 className="mt-4 text-lg font-semibold">No Attack Plans Found</h3>
          <p className="mt-2 text-sm text-muted-foreground">Get started by generating a new AI-powered attack plan.</p>
        </div>
      );
    }

    return (
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Threat Actor</TableHead>
            <TableHead className="text-right">Created</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {plansQuery.data.map((plan) => {
            const StatusIcon = statusConfig[plan.status].icon;
            return (
              <TableRow key={plan.id} onClick={() => setSelectedPlanId(plan.id)} className="cursor-pointer hover:bg-slate-800/50">
                <TableCell className="font-medium">{plan.name}</TableCell>
                <TableCell>
                  <Badge variant="outline" className="flex items-center gap-2">
                    <StatusIcon className={`h-3 w-3 ${statusConfig[plan.status].color} rounded-full`} />
                    <span className="capitalize">{plan.status}</span>
                  </Badge>
                </TableCell>
                <TableCell>{plan.threatActorProfile}</TableCell>
                <TableCell className="text-right">{new Date(plan.createdAt).toLocaleDateString()}</TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    );
  };

  const renderPlanDetails = () => {
    if (!selectedPlanId) {
      return <div className="p-8 text-center text-muted-foreground">Select a plan to view its details.</div>;
    }
    if (selectedPlanQuery.isLoading) {
      return <div className="flex justify-center items-center p-8"><Loader2 className="h-8 w-8 animate-spin" /></div>;
    }
    if (selectedPlanQuery.isError || !selectedPlanQuery.data) {
      return <div className="p-8 text-center text-red-500">Error loading plan details.</div>;
    }

    const plan = selectedPlanQuery.data;

    return (
      <Card className="h-full">
        <CardHeader>
          <div className="flex justify-between items-start">
            <div>
              <CardTitle>{plan.name}</CardTitle>
              <CardDescription>Threat Actor: {plan.threatActorProfile}</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              {plan.status === "ready" && (
                <Button size="sm" onClick={() => acceptMutation.mutate({ id: plan.id })} disabled={acceptMutation.isLoading}>
                  {acceptMutation.isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4 mr-2" />} Accept & Execute
                </Button>
              )}
              <Button variant="destructive" size="sm" onClick={() => deleteMutation.mutate({ id: plan.id })} disabled={deleteMutation.isLoading}>
                {deleteMutation.isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {plan.status === "generating" && (
            <div className="flex flex-col items-center justify-center text-center p-6 bg-slate-800/50 rounded-lg">
              <Bot className="h-10 w-10 text-blue-400 mb-4" />
              <h4 className="text-lg font-semibold">AI is Generating Plan</h4>
              <p className="text-sm text-muted-foreground mb-4">This may take a few moments. The plan details will appear here once completed.</p>
              <Progress value={plan.generationProgress ?? 33} className="w-full max-w-sm" />
            </div>
          )}
          <div>
            <h4 className="font-semibold mb-2">Target Description</h4>
            <p className="text-sm text-muted-foreground bg-slate-900 p-3 rounded-md">{plan.targetDescription}</p>
          </div>
          {plan.phases && plan.phases.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2">Attack Phases</h4>
              <div className="space-y-3">
                {plan.phases.map((phase, index) => (
                  <div key={index} className="p-3 border border-slate-700 rounded-lg">
                    <h5 className="font-semibold text-slate-300">Phase {index + 1}: {phase.name}</h5>
                    <ul className="mt-2 list-disc list-inside space-y-1 text-sm text-muted-foreground">
                      {phase.steps.map((step, stepIndex) => (
                        <li key={stepIndex}>
                          {step.description} <Badge variant="secondary">{step.mitreTechnique}</Badge>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="flex flex-col h-full p-4 md:p-6 space-y-4 bg-slate-900 text-white">
      <Card className="bg-slate-950/50 border-slate-800">
        <CardHeader>
          <div className="flex items-center gap-4">
            <Bot className="h-8 w-8 text-blue-400" />
            <div>
              <CardTitle className="text-xl">AI Attack Planner</CardTitle>
              <CardDescription>Use generative AI to create realistic attack plans based on target descriptions and threat actor profiles. Simulate sophisticated attacks to test your defenses.</CardDescription>
            </div>
          </div>
        </CardHeader>
      </Card>

      {renderStatCards()}

      <div className="grid md:grid-cols-3 gap-4 flex-1 min-h-0">
        <Card className="md:col-span-2 flex flex-col">
          <CardHeader className="flex flex-row justify-between items-center">
            <CardTitle>Attack Plans</CardTitle>
            <Dialog open={isGenerateDialogOpen} onOpenChange={setGenerateDialogOpen}>
              <DialogTrigger asChild>
                <Button><PlusCircle className="h-4 w-4 mr-2" /> Generate Plan</Button>
              </DialogTrigger>
              <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                  <DialogTitle>Generate New Attack Plan</DialogTitle>
                  <DialogDescription>Describe your target and select a threat profile. The AI will do the rest.</DialogDescription>
                </DialogHeader>
                <form onSubmit={handleGeneratePlan} className="grid gap-4 py-4">
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="name" className="text-right">Name</Label>
                    <Input id="name" name="name" required className="col-span-3" placeholder="e.g., Q3 Production Server Test" />
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="targetDescription" className="text-right">Target</Label>
                    <Input id="targetDescription" name="targetDescription" required className="col-span-3" placeholder="e.g., Public-facing web server running Ubuntu" />
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="threatActorProfile" className="text-right">Threat Actor</Label>
                    <Select name="threatActorProfile" required>
                      <SelectTrigger className="col-span-3">
                        <SelectValue placeholder="Select a profile" />
                      </SelectTrigger>
                      <SelectContent>
                        {profilesQuery.data?.map(profile => (
                          <SelectItem key={profile.id} value={profile.name}>{profile.name}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <DialogFooter>
                    <DialogClose asChild>
                      <Button type="button" variant="secondary">Cancel</Button>
                    </DialogClose>
                    <Button type="submit" disabled={generateMutation.isLoading}>
                      {generateMutation.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Generate
                    </Button>
                  </DialogFooter>
                </form>
              </DialogContent>
            </Dialog>
          </CardHeader>
          <CardContent className="flex-1 flex flex-col min-h-0">
            <Tabs value={statusFilter} onValueChange={(value) => setStatusFilter(value as PlanStatus | "all")}>
              <TabsList className="grid w-full grid-cols-5">
                <TabsTrigger value="all">All</TabsTrigger>
                <TabsTrigger value="ready">Ready</TabsTrigger>
                <TabsTrigger value="executing">Executing</TabsTrigger>
                <TabsTrigger value="generating">Generating</TabsTrigger>
                <TabsTrigger value="completed">Completed</TabsTrigger>
              </TabsList>
            </Tabs>
            <div className="mt-4 flex-1 overflow-y-auto">{renderPlanList()}</div>
          </CardContent>
        </Card>
        <div className="md:col-span-1 min-h-0 overflow-y-auto">
          {renderPlanDetails()}
        </div>
      </div>
    </div>
  );
}
