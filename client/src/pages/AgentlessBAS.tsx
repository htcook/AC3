import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { Play, Trash2, Eye, PlusCircle, FileText, AlertCircle, CheckCircle, XCircle, Loader2 } from "lucide-react";

const testTypes = ["cloud_api", "network_probe", "email_payload", "dns_exfil", "http_c2_sim"];

export default function AgentlessBAS() {
    const [statusFilter, setStatusFilter] = useState("all");
    const [isCreateDialogOpen, setCreateDialogOpen] = useState(false);

    const statsQuery = trpc.agentlessBAS.getStats.useQuery();
    const testsQuery = trpc.agentlessBAS.list.useQuery({
        status: statusFilter === "all" ? undefined : statusFilter,
    });

    const createMutation = trpc.agentlessBAS.create.useMutation({
        onSuccess: () => {
            toast.success("Test created successfully.");
            testsQuery.refetch();
            setCreateDialogOpen(false);
        },
        onError: (error) => {
            toast.error(`Failed to create test: ${error.message}`);
        }
    });

    const executeMutation = trpc.agentlessBAS.execute.useMutation({
        onSuccess: () => {
            toast.success("Test execution started.");
            testsQuery.refetch();
        },
        onError: (error) => {
            toast.error(`Failed to execute test: ${error.message}`);
        }
    });

    const deleteMutation = trpc.agentlessBAS.delete.useMutation({
        onSuccess: () => {
            toast.success("Test deleted successfully.");
            testsQuery.refetch();
        },
        onError: (error) => {
            toast.error(`Failed to delete test: ${error.message}`);
        }
    });

    const handleCreateTest = (event) => {
        event.preventDefault();
        const formData = new FormData(event.target);
        const data = Object.fromEntries(formData.entries());
        createMutation.mutate(data);
    };

    const StatCard = ({ title, value, icon }) => (
        <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">{title}</CardTitle>
                {icon}
            </CardHeader>
            <CardContent>
                <div className="text-2xl font-bold">{value}</div>
            </CardContent>
        </Card>
    );

    const StatusBadge = ({ status }) => {
        const variant = {
            pending: "secondary",
            running: "default",
            completed: "success",
            failed: "destructive",
        }[status];
        return <Badge variant={variant}>{status}</Badge>;
    };

    return (
        <div className="flex flex-col h-full p-4 sm:p-6 lg:p-8 bg-zinc-900 text-white">
            <Card className="mb-6 bg-slate-900 border-slate-800">
                <CardContent className="p-4">
                    <div className="flex items-center">
                        <FileText className="h-6 w-6 mr-3 text-blue-400" />
                        <p className="text-slate-300">
                            This page enables Agentless Breach & Attack Simulation (BAS). You can run various security validation tests like cloud API probes, network probes, and C2 simulations without deploying agents. Monitor test statuses, create new tests, and view detailed results to continuously assess your security posture.
                        </p>
                    </div>
                </CardContent>
            </Card>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
                <StatCard title="Total Tests" value={statsQuery.data?.total ?? 0} icon={<FileText className="h-4 w-4 text-muted-foreground" />} />
                <StatCard title="Completed" value={statsQuery.data?.completed ?? 0} icon={<CheckCircle className="h-4 w-4 text-green-500" />} />
                <StatCard title="Running" value={statsQuery.data?.running ?? 0} icon={<Loader2 className="h-4 w-4 text-blue-500 animate-spin" />} />
                <StatCard title="Failed" value={statsQuery.data?.failed ?? 0} icon={<XCircle className="h-4 w-4 text-red-500" />} />
            </div>

            <Card className="flex-grow bg-slate-900 border-slate-800">
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <CardTitle>Breach & Attack Simulation Tests</CardTitle>
                        <Dialog open={isCreateDialogOpen} onOpenChange={setCreateDialogOpen}>
                            <DialogTrigger asChild>
                                <Button><PlusCircle className="mr-2 h-4 w-4" /> Create Test</Button>
                            </DialogTrigger>
                            <DialogContent className="sm:max-w-[425px] bg-slate-950 text-white border-slate-800">
                                <DialogHeader>
                                    <DialogTitle>Create New BAS Test</DialogTitle>
                                </DialogHeader>
                                <form onSubmit={handleCreateTest} className="grid gap-4 py-4">
                                    <div className="grid grid-cols-4 items-center gap-4">
                                        <Label htmlFor="name" className="text-right">Name</Label>
                                        <Input id="name" name="name" className="col-span-3 bg-slate-800 border-slate-700" required />
                                    </div>
                                    <div className="grid grid-cols-4 items-center gap-4">
                                        <Label htmlFor="testType" className="text-right">Test Type</Label>
                                        <select id="testType" name="testType" className="col-span-3 bg-slate-800 border-slate-700 p-2 rounded-md" required>
                                            {testTypes.map(type => <option key={type} value={type}>{type}</option>)}
                                        </select>
                                    </div>
                                    <div className="grid grid-cols-4 items-center gap-4">
                                        <Label htmlFor="targetDescription" className="text-right">Target</Label>
                                        <Input id="targetDescription" name="targetDescription" placeholder="e.g., S3 bucket name, IP address" className="col-span-3 bg-slate-800 border-slate-700" />
                                    </div>
                                    <Button type="submit" disabled={createMutation.isLoading}>
                                        {createMutation.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Create
                                    </Button>
                                </form>
                            </DialogContent>
                        </Dialog>
                    </div>
                </CardHeader>
                <CardContent>
                    <Tabs value={statusFilter} onValueChange={setStatusFilter}>
                        <TabsList className="grid w-full grid-cols-5 bg-slate-800">
                            <TabsTrigger value="all">All</TabsTrigger>
                            <TabsTrigger value="pending">Pending</TabsTrigger>
                            <TabsTrigger value="running">Running</TabsTrigger>
                            <TabsTrigger value="completed">Completed</TabsTrigger>
                            <TabsTrigger value="failed">Failed</TabsTrigger>
                        </TabsList>
                    </Tabs>
                    <div className="mt-4">
                        {testsQuery.isLoading ? (
                            <div className="flex justify-center items-center h-64">
                                <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
                            </div>
                        ) : testsQuery.isError ? (
                            <div className="flex flex-col justify-center items-center h-64 text-red-500">
                                <AlertCircle className="h-8 w-8 mb-2" />
                                <span>Error loading tests: {testsQuery.error.message}</span>
                            </div>
                        ) : testsQuery.data.length === 0 ? (
                            <div className="flex flex-col justify-center items-center h-64 text-slate-400">
                                <FileText className="h-8 w-8 mb-2" />
                                <span>No tests found.</span>
                            </div>
                        ) : (
                            <Table>
                                <TableHeader>
                                    <TableRow className="border-slate-700 hover:bg-slate-800">
                                        <TableHead>Name</TableHead>
                                        <TableHead>Status</TableHead>
                                        <TableHead>Type</TableHead>
                                        <TableHead>Target</TableHead>
                                        <TableHead className="text-right">Actions</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {testsQuery.data.map((test) => (
                                        <TableRow key={test.id} className="border-slate-800 hover:bg-slate-800/50">
                                            <TableCell className="font-medium">{test.name}</TableCell>
                                            <TableCell><StatusBadge status={test.status} /></TableCell>
                                            <TableCell><Badge variant="outline">{test.testType}</Badge></TableCell>
                                            <TableCell className="text-slate-400">{test.targetDescription}</TableCell>
                                            <TableCell className="text-right">
                                                <Button variant="ghost" size="icon" onClick={() => executeMutation.mutate({ id: test.id })} disabled={test.status === 'running'}>
                                                    <Play className="h-4 w-4" />
                                                </Button>
                                                <Button variant="ghost" size="icon">
                                                    <Eye className="h-4 w-4" />
                                                </Button>
                                                <Button variant="ghost" size="icon" onClick={() => deleteMutation.mutate({ id: test.id })}>
                                                    <Trash2 className="h-4 w-4 text-red-500" />
                                                </Button>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        )}
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
