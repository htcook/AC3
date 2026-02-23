
"use client";

import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, AlertTriangle, Trash2, PlusCircle, Eye } from "lucide-react";

type ThreatActorProfile = 'apt28' | 'apt29' | 'apt41' | 'fin7' | 'lazarus' | 'custom';

const AiAttackPlannerPage = () => {
  const [isGenerateDialogOpen, setGenerateDialogOpen] = useState(false);
  const [selectedPlanId, setSelectedPlanId] = useState<number | null>(null);

  const utils = trpc.useUtils();
  const plansQuery = trpc.aiAttackPlanner.list.useQuery({});
  const generatePlanMutation = trpc.aiAttackPlanner.generate.useMutation({
    onSuccess: () => {
      toast.success("Attack plan generated successfully!");
      utils.aiAttackPlanner.list.invalidate();
      setGenerateDialogOpen(false);
    },
    onError: (error: any) => {
      toast.error("Failed to generate attack plan", { description: error.message });
    },
  });
  const deletePlanMutation = trpc.aiAttackPlanner.delete.useMutation({
    onSuccess: () => {
      toast.success("Attack plan deleted successfully!");
      utils.aiAttackPlanner.list.invalidate();
    },
    onError: (error: any) => {
      toast.error("Failed to delete attack plan", { description: error.message });
    },
  });

  const handleGenerateSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const data = Object.fromEntries(formData.entries());

    generatePlanMutation.mutate({
      name: data.name as string,
      targetDescription: data.targetDescription as string,
      threatActorProfile: data.threatActorProfile as ThreatActorProfile,
      environmentContext: data.environmentContext as string | undefined,
      constraints: data.constraints as string | undefined,
    });
  };

  const handleDelete = (id: number) => {
    if (window.confirm("Are you sure you want to delete this plan?")) {
      deletePlanMutation.mutate({ id });
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground p-4 sm:p-6 lg:p-8">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-2xl font-bold">AI-Driven Attack Planner</CardTitle>
            <CardDescription>Generate and manage LLM-powered attack plans.</CardDescription>
          </div>
          <Dialog open={isGenerateDialogOpen} onOpenChange={setGenerateDialogOpen}>
            <DialogTrigger asChild>
              <Button><PlusCircle className="mr-2 h-4 w-4" /> Generate Plan</Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[625px]">
              <form onSubmit={handleGenerateSubmit}>
                <DialogHeader>
                  <DialogTitle>Generate New Attack Plan</DialogTitle>
                  <DialogDescription>Describe your target and select a threat profile to generate a plan.</DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="name" className="text-right">Name</Label>
                    <Input id="name" name="name" className="col-span-3" required />
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="targetDescription" className="text-right">Target</Label>
                    <Textarea id="targetDescription" name="targetDescription" className="col-span-3" placeholder="Describe the target system or organization..." required />
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="threatActorProfile" className="text-right">Threat Actor</Label>
                    <Select name="threatActorProfile" required defaultValue="apt28">
                      <SelectTrigger className="col-span-3">
                        <SelectValue placeholder="Select a profile" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="apt28">APT28 (Fancy Bear)</SelectItem>
                        <SelectItem value="apt29">APT29 (Cozy Bear)</SelectItem>
                        <SelectItem value="apt41">APT41 (Barium)</SelectItem>
                        <SelectItem value="fin7">FIN7</SelectItem>
                        <SelectItem value="lazarus">Lazarus Group</SelectItem>
                        <SelectItem value="custom">Custom</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="environmentContext" className="text-right">Environment</Label>
                    <Textarea id="environmentContext" name="environmentContext" className="col-span-3" placeholder="(Optional) Provide context about the technical environment..." />
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="constraints" className="text-right">Constraints</Label>
                    <Textarea id="constraints" name="constraints" className="col-span-3" placeholder="(Optional) Specify any constraints or rules of engagement..." />
                  </div>
                </div>
                <DialogFooter>
                  <Button type="submit" disabled={generatePlanMutation.isPending}>
                    {generatePlanMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} 
                    Generate
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          {plansQuery.isLoading && (
            <div className="flex items-center justify-center p-10">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          )}
          {plansQuery.isError && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{plansQuery.error.message}</AlertDescription>
            </Alert>
          )}
          {plansQuery.isSuccess && (plansQuery.data?.length ?? 0) === 0 && (
            <div className="text-center text-muted-foreground p-10">
              <p className="mb-2">No attack plans found.</p>
              <p>Click "Generate Plan" to create your first one.</p>
            </div>
          )}
          {plansQuery.isSuccess && (plansQuery.data?.length ?? 0) > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Threat Actor</TableHead>
                  <TableHead>Risk Score</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(plansQuery.data ?? []).map((plan) => (
                  <TableRow key={plan.id}>
                    <TableCell className="font-medium">{plan.name}</TableCell>
                    <TableCell className="max-w-xs truncate">{plan.targetDescription}</TableCell>
                    <TableCell>{(plan.threatActorProfile || 'N/A').toUpperCase()}</TableCell>
                    <TableCell>{plan.estimatedRiskScore}</TableCell>
                    <TableCell><Badge variant={plan.status === 'completed' ? 'default' : 'secondary'}>{plan.status}</Badge></TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" onClick={() => setSelectedPlanId(plan.id)}>
                        <Eye className="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="icon" onClick={() => handleDelete(plan.id)} disabled={deletePlanMutation.isPending && deletePlanMutation.variables?.id === plan.id}>
                        {deletePlanMutation.isPending && deletePlanMutation.variables?.id === plan.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {selectedPlanId && (
        <PlanDetailsDialog planId={selectedPlanId} onOpenChange={() => setSelectedPlanId(null)} />
      )}
    </div>
  );
};

const PlanDetailsDialog = ({ planId, onOpenChange }: { planId: number; onOpenChange: (open: boolean) => void; }) => {
  const planQuery = trpc.aiAttackPlanner.get.useQuery({ id: planId });

  return (
    <Dialog open={true} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Attack Plan Details</DialogTitle>
        </DialogHeader>
        {planQuery.isLoading && (
          <div className="flex items-center justify-center p-10">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        )}
        {planQuery.isError && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{planQuery.error.message}</AlertDescription>
            </Alert>
        )}
        {planQuery.isSuccess && planQuery.data && (
          <div className="prose prose-invert max-w-none max-h-[70vh] overflow-y-auto">
            <h2 className="text-xl font-bold">{planQuery.data.name}</h2>
            <div className="grid grid-cols-2 gap-4 my-4">
                <p><strong>Threat Actor:</strong> {(planQuery.data.threatActorProfile || 'N/A').toUpperCase()}</p>
                <p><strong>Risk Score:</strong> {planQuery.data.estimatedRiskScore}</p>
                <p><strong>Status:</strong> <Badge variant={planQuery.data.status === 'completed' ? 'default' : 'secondary'}>{planQuery.data.status}</Badge></p>
                <p><strong>Created By:</strong> {planQuery.data.createdBy}</p>
            </div>
            
            <h3 className="font-semibold">Target Description</h3>
            <p>{planQuery.data.targetDescription}</p>

            {(planQuery.data.environmentContext as any) && <>
                <h3 className="font-semibold">Environment Context</h3>
                <p>{String(planQuery.data.environmentContext)}</p>
            </>}

            {(planQuery.data as any).constraints && <>
                <h3 className="font-semibold">Constraints</h3>
                <p>{String((planQuery.data as any).constraints)}</p>
            </>}

            <h3 className="font-semibold">Generated Plan</h3>
            <div className="p-4 bg-muted rounded-md text-sm">
                <pre className="whitespace-pre-wrap font-sans">{String(planQuery.data.generatedPlan)}</pre>
            </div>

            <h3 className="font-semibold">Attack Steps (MITRE ATT&CK)</h3>
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead>Tactic</TableHead>
                        <TableHead>Technique</TableHead>
                        <TableHead>Description</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {(planQuery.data.attackSteps as any[]).map((step: any, index: number) => (
                        <TableRow key={index}>
                            <TableCell>{step.tactic}</TableCell>
                            <TableCell><code>{step.techniqueId}</code>: {step.techniqueName}</TableCell>
                            <TableCell>{step.description}</TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
          </div>
        )}
        <DialogFooter>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default AiAttackPlannerPage;
