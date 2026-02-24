
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PlusCircle, Play, Trash2, Loader2, AlertCircle, BarChart, Network, ShieldCheck, ShieldAlert } from "lucide-react";
import AppShell from "@/components/AppShell";

type TestType = 'port_probe' | 'protocol_test' | 'lateral_movement' | 'exfiltration' | 'c2_callback' | 'segmentation';
type Status = 'pending' | 'running' | 'completed' | 'error';

const statusColors: Record<Status, string> = {
    pending: "bg-yellow-500/10 text-yellow-500",
    running: "bg-blue-500/10 text-blue-500",
    completed: "bg-green-500/10 text-green-500",
    error: "bg-red-500/10 text-red-500",
};

const resultColors: Record<'blocked' | 'allowed', string> = {
    allowed: "bg-green-500/10 text-green-500",
    blocked: "bg-red-500/10 text-red-500",
};

const CreateTestForm = ({ setOpen }: { setOpen: (open: boolean) => void }) => {
    const [name, setName] = useState("");
    const [testType, setTestType] = useState<TestType>('port_probe');
    const [sourceIp, setSourceIp] = useState("");
    const [targetIp, setTargetIp] = useState("");
    const [targetPort, setTargetPort] = useState("80");
    const [protocol, setProtocol] = useState<'tcp' | 'udp' | 'icmp'>('tcp');
    const [expectedResult, setExpectedResult] = useState<'blocked' | 'allowed'>('blocked');

    const utils = trpc.useUtils();
    const createTest = trpc.ngfwValidation.create.useMutation({
        onSuccess: () => {
            toast.success("Test created successfully!");
            utils.ngfwValidation.list.invalidate();
            utils.ngfwValidation.getStats.invalidate();
            setOpen(false);
        },
        onError: (error: any) => {
            toast.error("Failed to create test", { description: error.message });
        },
    });

    const handleSubmit = () => {
        createTest.mutate({ 
            name, 
            testType, 
            sourceIp, 
            targetIp, 
            targetPort: parseInt(targetPort, 10), 
            protocol, 
            expectedResult 
        });
    };

    return (
        <div className="grid gap-4 py-4">
            <Input placeholder="Test Name" value={name} onChange={(e: any) => setName(e.target.value)} />
            <Select onValueChange={(v: any) => setTestType(v)} defaultValue={testType}>
                <SelectTrigger><SelectValue placeholder="Test Type" /></SelectTrigger>
                <SelectContent>
                    <SelectItem value="port_probe">Port Probe</SelectItem>
                    <SelectItem value="protocol_test">Protocol Test</SelectItem>
                    <SelectItem value="lateral_movement">Lateral Movement</SelectItem>
                    <SelectItem value="exfiltration">Exfiltration</SelectItem>
                </SelectContent>
            </Select>
            <Input placeholder="Source IP" value={sourceIp} onChange={(e: any) => setSourceIp(e.target.value)} />
            <Input placeholder="Target IP" value={targetIp} onChange={(e: any) => setTargetIp(e.target.value)} />
            <Input type="number" placeholder="Target Port" value={targetPort} onChange={(e: any) => setTargetPort(e.target.value)} />
            <Select onValueChange={(v: any) => setProtocol(v)} defaultValue={protocol}>
                <SelectTrigger><SelectValue placeholder="Protocol" /></SelectTrigger>
                <SelectContent>
                    <SelectItem value="tcp">TCP</SelectItem>
                    <SelectItem value="udp">UDP</SelectItem>
                    <SelectItem value="icmp">ICMP</SelectItem>
                </SelectContent>
            </Select>
            <Select onValueChange={(v: any) => setExpectedResult(v)} defaultValue={expectedResult}>
                <SelectTrigger><SelectValue placeholder="Expected Result" /></SelectTrigger>
                <SelectContent>
                    <SelectItem value="blocked">Blocked</SelectItem>
                    <SelectItem value="allowed">Allowed</SelectItem>
                </SelectContent>
            </Select>
            <DialogFooter>
                <Button onClick={handleSubmit} disabled={createTest.isPending}>
                    {createTest.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Create Test
                </Button>
            </DialogFooter>
        </div>
    );
};

const StatsCards = () => {
    const { data, isLoading, error } = trpc.ngfwValidation.getStats.useQuery();

    if (isLoading) return <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">...Loading stats</div>;
    if (error) return <div className="text-red-500">Error loading stats: {error.message}</div>;
    if (!data) return null;

    return (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Total Tests</CardTitle>
                    <Network className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent><div className="text-2xl font-bold">{(data.completed + data.error + data.pending)}</div></CardContent>
            </Card>
            <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Match Rate</CardTitle>
                    <ShieldCheck className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                    <div className={`text-2xl font-bold ${0 > 90 ? 'text-green-500' : 'text-yellow-500'}`}>
                        N/A
                    </div>
                </CardContent>
            </Card>
            <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Ingress vs Egress</CardTitle>
                    <BarChart className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                    <div className="text-sm text-muted-foreground">
                        Completed: {data.completed}, Pending: {data.pending}
                    </div>
                </CardContent>
            </Card>
            <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Allowed vs Blocked</CardTitle>
                    <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                    <div className="text-sm text-muted-foreground">
                        Errors: {data.error}
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}

const NgfwValidationPage = () => {
    const [isDialogOpen, setDialogOpen] = useState(false);
    const [filters, setFilters] = useState<{ testType?: TestType, status?: Status }>({});

    const utils = trpc.useUtils();
    const { data: tests, isLoading, isError, error } = trpc.ngfwValidation.list.useQuery(filters as any, {
        staleTime: 5000,
    });

    const executeMutation = trpc.ngfwValidation.execute.useMutation({
        onSuccess: (data) => {
            toast.success(`Test #${data.success} executed successfully.`);
            utils.ngfwValidation.list.invalidate();
            utils.ngfwValidation.getStats.invalidate();
        },
        onError: (error: any) => {
            toast.error("Execution failed", { description: error.message });
        },
    });

    const deleteMutation = trpc.ngfwValidation.delete.useMutation({
        onSuccess: (_, variables) => {
            toast.success(`Test #${variables.id} deleted.`);
            utils.ngfwValidation.list.invalidate();
            utils.ngfwValidation.getStats.invalidate();
        },
        onError: (error: any) => {
            toast.error("Delete failed", { description: error.message });
        },
    });

    const handleFilterChange = (filterType: 'testType' | 'status', value: string) => {
        setFilters(prev => ({ ...prev, [filterType]: value === 'all' ? undefined : value }));
    };

    return (
    <AppShell activePath="/ngfw-validation">
      <div className="p-4 md:p-8 bg-background text-foreground min-h-screen">
            <header className="flex items-center justify-between mb-6">
                <h1 className="text-3xl font-bold">NGFW Validation</h1>
                <Dialog open={isDialogOpen} onOpenChange={setDialogOpen}>
                    <DialogTrigger asChild>
                        <Button><PlusCircle className="mr-2 h-4 w-4" /> Add Test</Button>
                    </DialogTrigger>
                    <DialogContent className="sm:max-w-[425px]">
                        <DialogHeader><DialogTitle>Create New Firewall Test</DialogTitle></DialogHeader>
                        <CreateTestForm setOpen={setDialogOpen} />
                    </DialogContent>
                </Dialog>
            </header>

            <main>
                <StatsCards />

                <Card className="mt-6">
                    <CardHeader>
                        <CardTitle>Validation Tests</CardTitle>
                        <div className="flex items-center space-x-4 pt-2">
                            <Select onValueChange={(v: any) => handleFilterChange('testType', v)}>
                                <SelectTrigger className="w-[180px]"><SelectValue placeholder="Filter by type..." /></SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="all">All Types</SelectItem>
                                    <SelectItem value="port_probe">Port Probe</SelectItem>
                                    <SelectItem value="protocol_test">Protocol Test</SelectItem>
                                    <SelectItem value="lateral_movement">Lateral Movement</SelectItem>
                                    <SelectItem value="exfiltration">Exfiltration</SelectItem>
                                </SelectContent>
                            </Select>
                            <Select onValueChange={(v: any) => handleFilterChange('status', v)}>
                                <SelectTrigger className="w-[180px]"><SelectValue placeholder="Filter by status..." /></SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="all">All Statuses</SelectItem>
                                    <SelectItem value="pending">Pending</SelectItem>
                                    <SelectItem value="running">Running</SelectItem>
                                    <SelectItem value="completed">Completed</SelectItem>
                                    <SelectItem value="failed">Failed</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    </CardHeader>
                    <CardContent>
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Name</TableHead>
                                    <TableHead>Type</TableHead>
                                    <TableHead>Source/Target</TableHead>
                                    <TableHead>Expected</TableHead>
                                    <TableHead>Actual</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead className="text-right">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {isLoading ? (
                                    <TableRow><TableCell colSpan={7} className="text-center"><Loader2 className="mx-auto h-8 w-8 animate-spin text-muted-foreground" /></TableCell></TableRow>
                                ) : isError ? (
                                    <TableRow><TableCell colSpan={7} className="text-center text-red-500"><AlertCircle className="mx-auto h-8 w-8" /><p className="mt-2">{error.message}</p></TableCell></TableRow>
                                ) : tests && tests.length > 0 ? (
                                    tests.map((test) => (
                                        <TableRow key={test.id}>
                                            <TableCell className="font-medium">{test.name}</TableCell>
                                            <TableCell><Badge variant="outline">{test.testType}</Badge></TableCell>
                                            <TableCell className="text-xs">{test.sourceIp} &rarr; {test.targetIp}:{test.targetPort}</TableCell>
                                            <TableCell><Badge className={resultColors[test.expectedResult]}>{test.expectedResult}</Badge></TableCell>
                                            <TableCell>
                                                {test.actualResult ? (
                                                    <Badge className={test.expectedResult === test.actualResult ? resultColors.allowed : resultColors.blocked}>
                                                        {test.actualResult}
                                                    </Badge>
                                                ) : 'N/A'}
                                            </TableCell>
                                            <TableCell><Badge className={statusColors[test.status as Status]}>{test.status}</Badge></TableCell>
                                            <TableCell className="text-right">
                                                <Button variant="ghost" size="icon" onClick={() => executeMutation.mutate({ id: test.id })} disabled={executeMutation.isPending || test.status === 'running'}>
                                                    <Play className="h-4 w-4" />
                                                </Button>
                                                <Button variant="ghost" size="icon" onClick={() => deleteMutation.mutate({ id: test.id })} disabled={deleteMutation.isPending}>
                                                    <Trash2 className="h-4 w-4" />
                                                </Button>
                                            </TableCell>
                                        </TableRow>
                                    ))
                                ) : (
                                    <TableRow><TableCell colSpan={7} className="text-center text-muted-foreground">No validation tests found.</TableCell></TableRow>
                                )}
                            </TableBody>
                        </Table>
                    </CardContent>
                </Card>
            </main>
        </div>
    </AppShell>
  );
};

export default NgfwValidationPage;
