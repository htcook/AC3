import { useState, useEffect, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { ShieldCheck, Play, Trash2, PlusCircle, FileText, BarChart2, AlertTriangle, Loader2 } from "lucide-react";

const ruleTypes = [
  'egress_filter',
  'lateral_movement',
  'dns_tunnel',
  'protocol_abuse',
  'data_exfil',
  'c2_beacon'
] as const;

type RuleType = typeof ruleTypes[number];

type Rule = {
  id: string;
  name: string;
  ruleType: RuleType;
  status: 'idle' | 'running' | 'completed' | 'error';
  targetHost?: string | null;
  targetPort?: number | null;
  protocol?: string | null;
  payload?: string | null;
  createdAt: Date;
};

const getStatusBadgeVariant = (status: Rule['status']) => {
  switch (status) {
    case 'running':
      return 'default'; // sonner's default is often a blue/purple
    case 'completed':
      return 'secondary';
    case 'error':
      return 'destructive';
    case 'idle':
    default:
      return 'outline';
  }
};

const getRuleTypeBadgeClass = (ruleType: RuleType) => {
  switch (ruleType) {
    case 'egress_filter': return 'border-cyan-400 text-cyan-400';
    case 'lateral_movement': return 'border-orange-400 text-orange-400';
    case 'dns_tunnel': return 'border-purple-400 text-purple-400';
    case 'protocol_abuse': return 'border-yellow-400 text-yellow-400';
    case 'data_exfil': return 'border-red-400 text-red-400';
    case 'c2_beacon': return 'border-pink-400 text-pink-400';
    default: return 'border-slate-500 text-slate-500';
  }
}

function CreateRuleDialog({ onRuleCreated }: { onRuleCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const [ruleType, setRuleType] = useState<RuleType | ''>('');
  const [targetHost, setTargetHost] = useState('');
  const [targetPort, setTargetPort] = useState('');
  const [protocol, setProtocol] = useState('');
  const [payload, setPayload] = useState('');

  const createRuleMutation = trpc.ngfwValidation.createRule.useMutation({
    onSuccess: () => {
      toast.success('Rule created successfully!');
      onRuleCreated();
      setOpen(false);
      // Reset form
      setName('');
      setRuleType('');
      setTargetHost('');
      setTargetPort('');
      setProtocol('');
      setPayload('');
    },
    onError: (error) => {
      toast.error(`Failed to create rule: ${error.message}`);
    },
  });

  const handleSubmit = () => {
    if (!name || !ruleType) {
      toast.warning('Rule Name and Rule Type are required.');
      return;
    }
    createRuleMutation.mutate({ 
      name, 
      ruleType, 
      targetHost: targetHost || undefined,
      targetPort: targetPort ? parseInt(targetPort, 10) : undefined,
      protocol: protocol || undefined,
      payload: payload || undefined,
    });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusCircle className="mr-2 h-4 w-4" />
          Create Rule
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[625px] bg-slate-900 border-slate-800 text-white">
        <DialogHeader>
          <DialogTitle>Create New Firewall Validation Rule</DialogTitle>
          <DialogDescription>
            Define a new rule to simulate a specific network attack vector.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="name" className="text-right">
              Rule Name
            </Label>
            <Input id="name" value={name} onChange={(e) => setName(e.target.value)} className="col-span-3 bg-slate-800 border-slate-700" placeholder="e.g., Test for Log4j C2 Beaconing" />
          </div>
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="ruleType" className="text-right">
              Rule Type
            </Label>
            <Select onValueChange={(value: RuleType) => setRuleType(value)} value={ruleType}>
                <SelectTrigger className="col-span-3 bg-slate-800 border-slate-700">
                    <SelectValue placeholder="Select an attack type" />
                </SelectTrigger>
                <SelectContent className="bg-slate-900 border-slate-800 text-white">
                    {ruleTypes.map(type => (
                        <SelectItem key={type} value={type} className="hover:bg-slate-800">{type.replace(/_/g, ' ')}</SelectItem>
                    ))}
                </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="targetHost" className="text-right">
              Target Host
            </Label>
            <Input id="targetHost" value={targetHost} onChange={(e) => setTargetHost(e.target.value)} className="col-span-3 bg-slate-800 border-slate-700" placeholder="Optional, e.g., 8.8.8.8" />
          </div>
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="targetPort" className="text-right">
              Target Port
            </Label>
            <Input id="targetPort" type="number" value={targetPort} onChange={(e) => setTargetPort(e.target.value)} className="col-span-3 bg-slate-800 border-slate-700" placeholder="Optional, e.g., 443" />
          </div>
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="protocol" className="text-right">
              Protocol
            </Label>
            <Input id="protocol" value={protocol} onChange={(e) => setProtocol(e.target.value)} className="col-span-3 bg-slate-800 border-slate-700" placeholder="Optional, e.g., TCP" />
          </div>
           <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="payload" className="text-right">
              Payload
            </Label>
            <Input id="payload" value={payload} onChange={(e) => setPayload(e.target.value)} className="col-span-3 bg-slate-800 border-slate-700" placeholder="Optional, e.g., base64 encoded data" />
          </div>
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="secondary">
              Cancel
            </Button>
          </DialogClose>
          <Button type="submit" onClick={handleSubmit} disabled={createRuleMutation.isLoading}>
            {createRuleMutation.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} 
            Create Rule
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ViewResultsDialog({ ruleId, ruleName }: { ruleId: string, ruleName: string }) {
  const [open, setOpen] = useState(false);
  const { data: results, isLoading, error } = trpc.ngfwValidation.getResults.useQuery(
    { id: ruleId },
    { enabled: open } // Only fetch when the dialog is open
  );

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" title="View Results">
          <FileText className="h-4 w-4" />
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl bg-slate-900 border-slate-800 text-white">
        <DialogHeader>
          <DialogTitle>Execution Results for "{ruleName}"</DialogTitle>
          <DialogDescription>
            Detailed results from the last execution of this validation rule.
          </DialogDescription>
        </DialogHeader>
        <div className="py-4 max-h-[60vh] overflow-y-auto">
          {isLoading ? (
            <div className="flex justify-center items-center p-8">
              <Loader2 className="h-8 w-8 animate-spin text-slate-500" />
            </div>
          ) : error ? (
            <div className="text-red-400 text-center p-8">
              <AlertTriangle className="h-8 w-8 mx-auto" />
              <p className="mt-2">Error loading results: {error.message}</p>
            </div>
          ) : results ? (
            <div className="space-y-4">
              <p><strong className="text-slate-300">Status:</strong> <Badge variant={results.success ? 'secondary' : 'destructive'}>{results.success ? 'Blocked' : 'Allowed'}</Badge></p>
              <p><strong className="text-slate-300">Timestamp:</strong> {new Date(results.timestamp).toLocaleString()}</p>
              <div>
                <strong className="text-slate-300">Log Output:</strong>
                <pre className="mt-2 p-3 bg-black rounded-md text-sm text-slate-300 overflow-x-auto">
                  <code>{results.log}</code>
                </pre>
              </div>
            </div>
          ) : (
            <div className="text-center p-8">
              <p className="text-slate-400">No results available for this rule yet.</p>
              <p className="text-sm text-slate-500">Execute the rule to generate results.</p>
            </div>
          )}
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="secondary">
              Close
            </Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function NgfwValidation() {
  const utils = trpc.useContext();
  const { data: stats, isLoading: isLoadingStats, error: statsError } = trpc.ngfwValidation.getStats.useQuery();
  const { data: rules, isLoading: isLoadingRules, error: rulesError, refetch: refetchRules } = trpc.ngfwValidation.listRules.useQuery(undefined, {
    refetchInterval: (data) => {
      // If any rule is currently running, poll every 3 seconds
      if (data?.some(rule => rule.status === 'running')) {
        return 3000;
      }
      // Otherwise, disable polling
      return false;
    },
  });

  const onRuleCreated = useCallback(() => {
    refetchRules();
    utils.ngfwValidation.getStats.invalidate();
  }, [refetchRules, utils.ngfwValidation.getStats]);

  // Refetch stats if rules change (e.g. after deletion)
  useEffect(() => {
    utils.ngfwValidation.getStats.invalidate();
  }, [rules, utils.ngfwValidation.getStats]);

  const executeRuleMutation = trpc.ngfwValidation.executeRule.useMutation({
    onSuccess: (data, variables) => {
      toast.success(`Rule "${rules?.find(r => r.id === variables.id)?.name}" executed successfully.`);
      utils.ngfwValidation.listRules.invalidate();
      utils.ngfwValidation.getStats.invalidate();
    },
    onError: (error, variables) => {
      toast.error(`Failed to execute rule "${rules?.find(r => r.id === variables.id)?.name}": ${error.message}`);
      utils.ngfwValidation.listRules.invalidate();
    },
  });

  const deleteRuleMutation = trpc.ngfwValidation.deleteRule.useMutation({
    onSuccess: (data, variables) => {
      toast.success(`Rule deleted successfully.`);
      utils.ngfwValidation.listRules.invalidate();
      utils.ngfwValidation.getStats.invalidate();
    },
    onError: (error) => {
      toast.error(`Failed to delete rule: ${error.message}`);
    },
  });

  const handleExecuteRule = (ruleId: string) => {
    executeRuleMutation.mutate({ id: ruleId });
  };

  const handleDeleteRule = (ruleId: string) => {
    deleteRuleMutation.mutate({ id: ruleId });
  };

  return (
    <div className="flex flex-col h-full bg-zinc-900 text-white p-6">
      <Card className="mb-6 bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle className="flex items-center text-2xl">
            <ShieldCheck className="mr-3 text-blue-400" />
            Next-Generation Firewall (NGFW) Validation
          </CardTitle>
          <CardDescription className="text-slate-400 pt-2">
            This page allows you to test the effectiveness of your network security controls. Simulate various attack techniques like egress filtering bypass, lateral movement, and data exfiltration to validate your NGFW rules and policies.
          </CardDescription>
        </CardHeader>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="text-lg flex items-center justify-between">
              Effectiveness Score
              <BarChart2 className="text-slate-500" />
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingStats ? (
              <Loader2 className="h-8 w-8 animate-spin text-slate-500" />
            ) : stats ? (
              <>
                <p className={`text-4xl font-bold ${stats.effectiveness > 80 ? 'text-green-400' : stats.effectiveness > 60 ? 'text-yellow-400' : 'text-red-400'}`}>
                  {stats.effectiveness.toFixed(1)}%
                </p>
                <Progress value={stats.effectiveness} className="mt-2 h-2" />
              </>
            ) : (
              <p className="text-sm text-slate-500">No data</p>
            )}
          </CardContent>
        </Card>
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="text-lg flex items-center justify-between">
              Rules Executed
              <Play className="text-slate-500" />
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingStats ? (
              <Loader2 className="h-8 w-8 animate-spin text-slate-500" />
            ) : stats ? (
              <p className="text-4xl font-bold">{stats.rulesExecuted}</p>
            ) : (
              <p className="text-sm text-slate-500">No data</p>
            )}
          </CardContent>
        </Card>
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="text-lg flex items-center justify-between">
              Detections
              <ShieldCheck className="text-slate-500" />
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingStats ? (
              <Loader2 className="h-8 w-8 animate-spin text-slate-500" />
            ) : stats ? (
              <p className="text-4xl font-bold">{stats.detections}</p>
            ) : (
              <p className="text-sm text-slate-500">No data</p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="flex-grow bg-slate-900 border-slate-800">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Firewall Validation Rules</CardTitle>
          <CreateRuleDialog onRuleCreated={onRuleCreated} />
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="border-slate-700 hover:bg-slate-800/50">
                <TableHead className="text-white">Rule Name</TableHead>
                <TableHead className="text-white">Type</TableHead>
                <TableHead className="text-white">Status</TableHead>
                <TableHead className="text-right text-white">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoadingRules ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-12">
                    <Loader2 className="h-8 w-8 animate-spin text-slate-500 mx-auto" />
                    <p className="text-slate-400 mt-2">Loading rules...</p>
                  </TableCell>
                </TableRow>
              ) : rulesError ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-12 text-red-400">
                    <AlertTriangle className="h-8 w-8 mx-auto" />
                    <p className="mt-2">Error loading rules: {rulesError.message}</p>
                  </TableCell>
                </TableRow>
              ) : rules && rules.length > 0 ? (
                rules.map((rule) => (
                  <TableRow key={rule.id} className="border-slate-800 hover:bg-slate-800/50">
                    <TableCell className="font-medium">{rule.name}</TableCell>
                    <TableCell><Badge variant="outline" className={getRuleTypeBadgeClass(rule.ruleType)}>{rule.ruleType.replace(/_/g, ' ')}</Badge></TableCell>
                    <TableCell><Badge variant={getStatusBadgeVariant(rule.status)}>{rule.status}</Badge></TableCell>
                    <TableCell className="text-right">
                      <Button 
                        variant="ghost" 
                        size="icon" 
                        title="Execute Rule"
                        onClick={() => handleExecuteRule(rule.id)}
                        disabled={executeRuleMutation.isLoading && executeRuleMutation.variables?.id === rule.id || rule.status === 'running'}
                      >
                        {executeRuleMutation.isLoading && executeRuleMutation.variables?.id === rule.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Play className="h-4 w-4" />
                        )}
                      </Button>
                      <ViewResultsDialog ruleId={rule.id} ruleName={rule.name} />
                      <Dialog>
                        <DialogTrigger asChild>
                           <Button variant="ghost" size="icon" className="text-red-500 hover:text-red-400" title="Delete Rule" disabled={deleteRuleMutation.isLoading}>
                             <Trash2 className="h-4 w-4" />
                           </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-[425px] bg-slate-900 border-slate-800 text-white">
                          <DialogHeader>
                            <DialogTitle>Confirm Deletion</DialogTitle>
                            <DialogDescription>
                              Are you sure you want to delete the rule "{rule.name}"? This action cannot be undone.
                            </DialogDescription>
                          </DialogHeader>
                          <DialogFooter>
                            <DialogClose asChild>
                              <Button type="button" variant="secondary">Cancel</Button>
                            </DialogClose>
                            <Button 
                              type="button" 
                              variant="destructive" 
                              onClick={() => handleDeleteRule(rule.id)} 
                              disabled={deleteRuleMutation.isLoading}
                            >
                              {deleteRuleMutation.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} 
                              Delete
                            </Button>
                          </DialogFooter>
                        </DialogContent>
                      </Dialog>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-12">
                    <p className="text-slate-400">No firewall validation rules found.</p>
                    <p className="text-sm text-slate-500">Get started by creating a new rule.</p>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
