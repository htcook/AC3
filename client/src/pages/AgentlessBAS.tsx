"use client";

import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle 
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogTrigger 
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { 
  AlertCircle, 
  CheckCircle, 
  ChevronRight, 
  Loader2, 
  Play, 
  Plus, 
  Trash2, 
  XCircle 
} from "lucide-react";
import AppShell from "@/components/AppShell";

const testTypes = ['cloud_api', 'network_probe', 'email_payload', 'dns_exfil', 'http_c2_sim'] as const;
type TestType = typeof testTypes[number];

const statusTypes = ['pending', 'running', 'completed', 'failed'] as const;
type StatusType = typeof statusTypes[number];

function StatusBadge({ status }: { status: StatusType }) {
  switch (status) {
    case 'pending':
      return <Badge variant="outline">Pending</Badge>;
    case 'running':
      return <Badge className="bg-blue-500 text-white">Running</Badge>;
    case 'completed':
      return <Badge className="bg-green-500 text-white">Completed</Badge>;
    case 'failed':
      return <Badge variant="destructive">Failed</Badge>;
    default:
      return <Badge>{status}</Badge>;
  }
}

function ResultBadge({ result }: { result: string | null | undefined }) {
    if (!result) return null;
    switch (result.toLowerCase()) {
        case 'blocked':
            return <Badge className="bg-red-600 text-white">Blocked</Badge>;
        case 'allowed':
            return <Badge className="bg-green-600 text-white">Allowed</Badge>;
        case 'error':
            return <Badge variant="destructive">Error</Badge>;
        default:
            return <Badge variant="secondary">{result}</Badge>;
    }
}

function CreateTestForm({ setOpen }: { setOpen: (open: boolean) => void }) {
  const utils = trpc.useUtils();
  const [name, setName] = useState("");
  const [testType, setTestType] = useState<TestType>('network_probe');
  const [targetDescription, setTargetDescription] = useState("");

  const createTestMutation = trpc.agentlessBAS.create.useMutation({
    onSuccess: () => {
      toast.success("Test created successfully.");
      utils.agentlessBAS.list.invalidate();
      utils.agentlessBAS.getStats.invalidate();
      setOpen(false);
    },
    onError: (error: any) => {
      toast.error("Failed to create test: " + error.message);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !targetDescription) {
        toast.warning("Please fill in all fields.");
        return;
    }
    createTestMutation.mutate({ name, testType, targetDescription });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="name" className="block text-sm font-medium text-gray-400 mb-1">Test Name</label>
        <Input id="name" value={name} onChange={(e: any) => setName(e.target.value)} placeholder="e.g., Internal Network Scan" />
      </div>
      <div>
        <label htmlFor="testType" className="block text-sm font-medium text-gray-400 mb-1">Test Type</label>
        <Select onValueChange={(value: TestType) => setTestType(value)} defaultValue={testType}>
            <SelectTrigger>
                <SelectValue placeholder="Select a test type" />
            </SelectTrigger>
            <SelectContent>
                {testTypes.map(type => <SelectItem key={type} value={type}>{type.toUpperCase()}</SelectItem>)}
            </SelectContent>
        </Select>
      </div>
      <div>
        <label htmlFor="target" className="block text-sm font-medium text-gray-400 mb-1">Target Description</label>
        <Input id="target" value={targetDescription} onChange={(e: any) => setTargetDescription(e.target.value)} placeholder="e.g., 10.0.0.0/24" />
      </div>
      <div className="flex justify-end">
        <Button type="submit" disabled={createTestMutation.isPending}>
          {createTestMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Create Test
        </Button>
      </div>
    </form>
  );
}

function ResultsDialog({ testId }: { testId: number }) {
    const { data: test, isLoading, isError, error } = trpc.agentlessBAS.getResults.useQuery({ id: testId });

    return (
        <DialogContent className="max-w-2xl bg-background text-foreground">
            <DialogHeader>
                <DialogTitle>Test Results: {test?.name}</DialogTitle>
            </DialogHeader>
            {isLoading && <div className="flex justify-center items-center p-8"><Loader2 className="h-8 w-8 animate-spin" /></div>}
            {isError && <div className="text-red-500 p-4"><AlertCircle className="inline-block mr-2"/>Error: {error.message}</div>}
            {test && (
                <div className="space-y-4 text-sm">
                    <div className="grid grid-cols-2 gap-4">
                        <div><strong>ID:</strong> {test.id}</div>
                        <div><strong>Status:</strong> <StatusBadge status={test.status as StatusType} /></div>
                        <div><strong>Test Type:</strong> <Badge variant="secondary">{(test.testType || '').toUpperCase()}</Badge></div>
                        <div><strong>Result:</strong> <ResultBadge result={test.result} /></div>
                    </div>
                    <div><strong>Target:</strong> <p className="font-mono p-2 bg-gray-800 rounded">{test.targetDescription}</p></div>
                    {test.techniqueName && <div><strong>Technique:</strong> {test.techniqueName} ({test.techniqueId})</div>}
                    <div><strong>Executed At:</strong> {test.executedAt ? new Date(test.executedAt).toLocaleString() : 'N/A'}</div>
                    <div><strong>Duration:</strong> {test.durationMs}ms</div>
                    <div className="space-y-2">
                        <strong>Result Details:</strong>
                        <pre className="p-4 bg-gray-900 rounded-md text-xs overflow-auto">{test.resultDetails ? JSON.stringify(test.resultDetails, null, 2) : "No details available."}</pre>
                    </div>
                </div>
            )}
        </DialogContent>
    )
}

export default function AgentlessBASPage() {
  const [filters, setFilters] = useState<{ status?: StatusType, testType?: TestType }>({});
  const [createTestOpen, setCreateTestOpen] = useState(false);
  const [resultsTestId, setResultsTestId] = useState<number | null>(null);

  const utils = trpc.useUtils();

  const statsQuery = trpc.agentlessBAS.getStats.useQuery();
  const listQuery = trpc.agentlessBAS.list.useQuery(filters as any);

  const executeMutation = trpc.agentlessBAS.execute.useMutation({
    onSuccess: (data) => {
      toast.success(`Test "${data.result}" started successfully.`);
      utils.agentlessBAS.list.invalidate();
      utils.agentlessBAS.getStats.invalidate();
    },
    onError: (error: any) => {
      toast.error("Failed to execute test: " + error.message);
    },
  });

  const deleteMutation = trpc.agentlessBAS.delete.useMutation({
    onSuccess: () => {
      toast.success("Test deleted successfully.");
      utils.agentlessBAS.list.invalidate();
      utils.agentlessBAS.getStats.invalidate();
    },
    onError: (error: any) => {
      toast.error("Failed to delete test: " + error.message);
    },
  });

  const handleFilterChange = (key: 'status' | 'testType', value: string) => {
    const val = value === 'all' ? undefined : value;
    setFilters(prev => ({ ...prev, [key]: val as any }));
  }

  return (
    <AppShell activePath="/agentless-bas">
      <div className="p-6 bg-background text-foreground min-h-screen">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Agentless BAS</h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Run breach and attack simulations without deploying agents on target systems. This page lets you configure and execute agentless security validation tests that probe your defenses from the outside — testing firewall rules, IDS/IPS detection, and network segmentation. Start a new simulation, monitor running tests, and review results to identify gaps in your security controls.</p>
        <Dialog open={createTestOpen} onOpenChange={setCreateTestOpen}>
          <DialogTrigger asChild>
            <Button><Plus className="mr-2 h-4 w-4" /> Create Test</Button>
          </DialogTrigger>
          <DialogContent className="bg-background text-foreground">
            <DialogHeader>
              <DialogTitle>Create New Agentless Test</DialogTitle>
            </DialogHeader>
            <CreateTestForm setOpen={setCreateTestOpen} />
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Tests</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {statsQuery.isLoading ? <Loader2 className="h-6 w-6 animate-spin" /> : <div className="text-2xl font-bold">{(statsQuery.data ?? []).reduce((a: number, s: any) => a + (s.total || 0), 0)}</div>}
          </CardContent>
        </Card>
        {(statsQuery.data ?? []).map((s: any) => (
            <Card key={s.status}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">{String(s.status).charAt(0).toUpperCase() + String(s.status).slice(1)}</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="text-2xl font-bold">{String(s.total)}</div>
                </CardContent>
            </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <CardTitle>Tests</CardTitle>
            <div className="flex items-center space-x-2">
                <Select onValueChange={(v: any) => handleFilterChange('status', v)}>
                    <SelectTrigger className="w-[180px]">
                        <SelectValue placeholder="Filter by status" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Statuses</SelectItem>
                        {statusTypes.map(s => <SelectItem key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</SelectItem>)}
                    </SelectContent>
                </Select>
                <Select onValueChange={(v: any) => handleFilterChange('testType', v)}>
                    <SelectTrigger className="w-[180px]">
                        <SelectValue placeholder="Filter by type" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Types</SelectItem>
                        {testTypes.map(t => <SelectItem key={t} value={t}>{t.toUpperCase()}</SelectItem>)}
                    </SelectContent>
                </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Result</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {listQuery.isLoading && (
                <TableRow><TableCell colSpan={6} className="text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin" /></TableCell></TableRow>
              )}
              {listQuery.isError && (
                <TableRow><TableCell colSpan={6} className="text-center text-red-500"><AlertCircle className="inline-block mr-2"/>Could not load tests: {listQuery.error.message}</TableCell></TableRow>
              )}
              {listQuery.isSuccess && listQuery.data.length === 0 && (
                <TableRow><TableCell colSpan={6} className="text-center">No tests found.</TableCell></TableRow>
              )}
              {listQuery.isSuccess && listQuery.data.map((test) => (
                <TableRow key={test.id}>
                  <TableCell className="font-medium">{test.name}</TableCell>
                  <TableCell><Badge variant="secondary">{(test.testType || '').toUpperCase()}</Badge></TableCell>
                  <TableCell className="font-mono text-xs">{test.targetDescription}</TableCell>
                  <TableCell><StatusBadge status={test.status as StatusType} /></TableCell>
                  <TableCell><ResultBadge result={test.result} /></TableCell>
                  <TableCell className="text-right space-x-2">
                    <Dialog>
                        <DialogTrigger asChild>
                            <Button variant="outline" size="sm" onClick={() => setResultsTestId(test.id)} disabled={test.status !== 'completed' && test.status !== 'failed'}>
                                View <ChevronRight className="h-4 w-4" />
                            </Button>
                        </DialogTrigger>
                        {resultsTestId === test.id && <ResultsDialog testId={test.id} key={test.id} />}
                    </Dialog>
                    <Button variant="outline" size="sm" onClick={() => executeMutation.mutate({ id: test.id })} disabled={executeMutation.isPending || test.status === 'running'}>
                      {executeMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                    </Button>
                    <Button variant="destructive" size="sm" onClick={() => deleteMutation.mutate({ id: test.id })} disabled={deleteMutation.isPending}>
                      {deleteMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
    </AppShell>
  );
}
