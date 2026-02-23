import { useState, useMemo, useCallback } from 'react';
import { trpc } from '@/lib/trpc';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogClose } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Progress } from '@/components/ui/progress';
import { toast } from 'sonner';
import { Info, Play, Plus, Trash2, Zap, Loader2, AlertCircle, CheckCircle, XCircle, ShieldCheck, FileText } from 'lucide-react';

const CreateTaskForm = ({ setOpen }) => {
  const [findingId, setFindingId] = useState('');
  const [findingTitle, setFindingTitle] = useState('');
  const [remediationType, setRemediationType] = useState('');

  const utils = trpc.useContext();
  const createTaskMutation = trpc.remediationVerification.createTask.useMutation({
    onSuccess: () => {
      toast.success('Task created successfully!');
      utils.remediationVerification.listTasks.invalidate();
      utils.remediationVerification.getStats.invalidate();
      setOpen(false);
    },
    onError: (error) => {
      toast.error('Failed to create task', { description: error.message });
    },
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    createTaskMutation.mutate({ findingId, findingTitle, remediationType });
  };

  return (
    <form onSubmit={handleSubmit} className="grid gap-4 py-4">
      <div className="grid grid-cols-4 items-center gap-4">
        <Label htmlFor="findingId" className="text-right text-zinc-400">Finding ID</Label>
        <Input id="findingId" value={findingId} onChange={(e) => setFindingId(e.target.value)} className="col-span-3 bg-zinc-800 border-zinc-700" />
      </div>
      <div className="grid grid-cols-4 items-center gap-4">
        <Label htmlFor="findingTitle" className="text-right text-zinc-400">Finding Title</Label>
        <Input id="findingTitle" value={findingTitle} onChange={(e) => setFindingTitle(e.target.value)} className="col-span-3 bg-zinc-800 border-zinc-700" />
      </div>
      <div className="grid grid-cols-4 items-center gap-4">
        <Label htmlFor="remediationType" className="text-right text-zinc-400">Remediation Type</Label>
        <Select onValueChange={setRemediationType} value={remediationType}>
            <SelectTrigger className="col-span-3 bg-zinc-800 border-zinc-700	text-white">
                <SelectValue placeholder="Select a type" />
            </SelectTrigger>
            <SelectContent className="bg-zinc-900 border-zinc-800 text-white">
                <SelectItem value="patch">Patch</SelectItem>
                <SelectItem value="config_change">Config Change</SelectItem>
                <SelectItem value="access_control">Access Control</SelectItem>
                <SelectItem value="network_segmentation">Network Segmentation</SelectItem>
                <SelectItem value="custom">Custom</SelectItem>
            </SelectContent>
        </Select>
      </div>
      <DialogFooter>
        <DialogClose asChild>
            <Button type="button" variant="secondary">Cancel</Button>
        </DialogClose>
        <Button type="submit" disabled={createTaskMutation.isLoading} className="bg-blue-600 hover:bg-blue-700 text-white">
          {createTaskMutation.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Create
        </Button>
      </DialogFooter>
    </form>
  );
};

const VerificationResultsDialog = ({ taskId, open, setOpen }) => {
    const resultsQuery = trpc.remediationVerification.getResults.useQuery({ id: taskId }, { enabled: !!taskId });

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogContent className="bg-zinc-950 border-zinc-800 text-white max-w-2xl">
                <DialogHeader>
                    <DialogTitle>Verification Results</DialogTitle>
                    <DialogDescription>Detailed results for verification task {taskId}</DialogDescription>
                </DialogHeader>
                {resultsQuery.isLoading ? (
                    <div className="flex justify-center items-center p-10"><Loader2 className="h-8 w-8 animate-spin text-zinc-400" /></div>
                ) : resultsQuery.error ? (
                    <div className="flex justify-center items-center p-10 text-red-500
                    "><AlertCircle className="h-6 w-6 mr-2" /> Error loading results.</div>
                ) : (
                    <div className="text-sm text-zinc-300 space-y-4">
                        <p><strong>Status:</strong> <Badge variant={resultsQuery.data.success ? 'success' : 'destructive'}>{resultsQuery.data.success ? 'Verified' : 'Failed'}</Badge></p>
                        <p><strong>Timestamp:</strong> {new Date(resultsQuery.data.timestamp).toLocaleString()}</p>
                        <div>
                            <strong>Output:</strong>
                            <pre className="bg-zinc-900 p-4 rounded-md mt-2 text-xs overflow-auto">{resultsQuery.data.output}</pre>
                        </div>
                    </div>
                )}
            </DialogContent>
        </Dialog>
    )
}

const RemediationVerification = () => {
  const [activeTab, setActiveTab] = useState('all');
  const [isCreateTaskOpen, setCreateTaskOpen] = useState(false);
  const [selectedTaskId, setSelectedTaskId] = useState(null);

  const tasksQuery = trpc.remediationVerification.listTasks.useQuery(
    activeTab === 'all' ? {} : { status: [activeTab] },
    { keepPreviousData: true }
  );

  const statsQuery = trpc.remediationVerification.getStats.useQuery();
  const utils = trpc.useContext();

  const executeVerificationMutation = trpc.remediationVerification.executeVerification.useMutation({
    onSuccess: () => {
      toast.success('Verification started!');
      utils.remediationVerification.listTasks.invalidate();
    },
    onError: (error) => {
      toast.error('Failed to start verification', { description: error.message });
    },
  });

  const deleteTaskMutation = trpc.remediationVerification.deleteTask.useMutation({
    onSuccess: () => {
      toast.success('Task deleted successfully!');
      utils.remediationVerification.listTasks.invalidate();
      utils.remediationVerification.getStats.invalidate();
    },
    onError: (error) => {
      toast.error('Failed to delete task', { description: error.message });
    },
  });

  const getStatusVariant = (status) => {
    switch (status) {
      case 'verified': return 'success';
      case 'in_progress': return 'default';
      case 'pending': return 'secondary';
      case 'failed': return 'destructive';
      case 'skipped': return 'outline';
      default: return 'default';
    }
  };

  return (
    <div className="min-h-screen bg-zinc-900 text-white p-8 font-sans">
      <Card className="bg-zinc-950 border-zinc-800 mb-8">
        <CardHeader>
          <div className="flex items-center space-x-4">
            <ShieldCheck className="h-8 w-8 text-blue-400" />
            <div>
              <CardTitle className="text-xl text-zinc-200">Remediation Verification</CardTitle>
              <CardDescription className="text-zinc-400">
                Automated remediation verification. Track and verify that security findings have been properly remediated.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {statsQuery.isLoading ? (
          <Card className="bg-zinc-950 border-zinc-800 flex items-center justify-center p-6 col-span-4	min-h-[120px]"><Loader2 className="h-6 w-6 animate-spin text-zinc-400" /></Card>
        ) : statsQuery.error ? (
          <Card className="bg-zinc-950 border-zinc-800 flex items-center justify-center p-6 col-span-4 min-h-[120px]"><AlertCircle className="h-6 w-6 text-red-500 mr-2" /> Error loading stats.</Card>
        ) : (
          <>
            <Card className="bg-zinc-950 border-zinc-800">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400">Total Tasks</CardTitle>
                <Zap className="h-4 w-4 text-zinc-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-zinc-200">{statsQuery.data?.total}</div>
                <p className="text-xs text-zinc-500">All verification tasks</p>
              </CardContent>
            </Card>
            <Card className="bg-zinc-950 border-zinc-800">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400">Verified</CardTitle>
                <CheckCircle className="h-4 w-4 text-green-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-zinc-200">{statsQuery.data?.verified}</div>
                <Progress value={(statsQuery.data?.verified / statsQuery.data?.total) * 100} className="h-2 mt-2" />
              </CardContent>
            </Card>
            <Card className="bg-zinc-950 border-zinc-800">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400">Pending</CardTitle>
                <Loader2 className="h-4 w-4 text-yellow-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-zinc-200">{statsQuery.data?.pending}</div>
                 <Progress value={(statsQuery.data?.pending / statsQuery.data?.total) * 100} className="h-2 mt-2" />
              </CardContent>
            </Card>
            <Card className="bg-zinc-950 border-zinc-800">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400">Failed</CardTitle>
                <XCircle className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-zinc-200">{statsQuery.data?.failed}</div>
                 <Progress value={(statsQuery.data?.failed / statsQuery.data?.total) * 100} className="h-2 mt-2" />
              </CardContent>
            </Card>
          </>
        )}
      </div>

      <Card className="bg-zinc-950 border-zinc-800">
        <CardHeader className="flex items-center justify-between">
          <CardTitle className="text-zinc-200">Verification Task List</CardTitle>
          <Dialog open={isCreateTaskOpen} onOpenChange={setCreateTaskOpen}>
            <DialogTrigger asChild>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white"><Plus className="mr-2 h-4 w-4" /> Create Task</Button>
            </DialogTrigger>
            <DialogContent className="bg-zinc-950 border-zinc-800 text-white">
              <DialogHeader>
                <DialogTitle>Create New Verification Task</DialogTitle>
                <DialogDescription>Link a task to a finding and define verification parameters.</DialogDescription>
              </DialogHeader>
              <CreateTaskForm setOpen={setCreateTaskOpen} />
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-6 bg-zinc-800 text-zinc-300">
              <TabsTrigger value="all">All</TabsTrigger>
              <TabsTrigger value="pending">Pending</TabsTrigger>
              <TabsTrigger value="in_progress">In Progress</TabsTrigger>
              <TabsTrigger value="verified">Verified</TabsTrigger>
              <TabsTrigger value="failed">Failed</TabsTrigger>
              <TabsTrigger value="skipped">Skipped</TabsTrigger>
            </TabsList>
            <TabsContent value={activeTab} className="mt-4">
              {tasksQuery.isLoading ? (
                <div className="flex justify-center items-center p-10
                "><Loader2 className="h-8 w-8 animate-spin text-zinc-400" /></div>
              ) : tasksQuery.error ? (
                <div className="flex justify-center items-center p-10 text-red-500
                "><AlertCircle className="h-6 w-6 mr-2" /> Error loading tasks.</div>
              ) : tasksQuery.data.length === 0 ? (
                <div className="text-center text-zinc-500 py-10">No tasks found for this category.</div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-zinc-900">
                      <TableHead className="text-zinc-400">Finding</TableHead>
                      <TableHead className="text-zinc-400">Status</TableHead>
                      <TableHead className="text-zinc-400">Remediation Type</TableHead>
                      <TableHead className="text-zinc-400">Assigned To</TableHead>
                      <TableHead className="text-right text-zinc-400">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {tasksQuery.data.map((task) => (
                      <TableRow key={task.id} className="border-zinc-800 hover:bg-zinc-900">
                        <TableCell>
                          <div className="font-medium text-zinc-200">{task.findingTitle}</div>
                          <div className="text-sm text-zinc-500">{task.findingId}</div>
                        </TableCell>
                        <TableCell><Badge variant={getStatusVariant(task.status)}>{task.status}</Badge></TableCell>
                        <TableCell><Badge variant="outline" className="border-zinc-600 text-zinc-300">{task.remediationType}</Badge></TableCell>
                        <TableCell className="text-zinc-300">{task.assignedTo}</TableCell>
                        <TableCell className="text-right">
                          <Button 
                            variant="ghost" 
                            size="icon" 
                            className="hover:bg-zinc-800 text-blue-400"
                            title="View Results"
                            onClick={() => setSelectedTaskId(task.id)}
                          >
                            <FileText className="h-4 w-4" />
                          </Button>
                          <Button 
                            variant="ghost" 
                            size="icon" 
                            className="hover:bg-zinc-800 text-green-400"
                            title="Execute Verification"
                            onClick={() => executeVerificationMutation.mutate({ id: task.id })}
                            disabled={executeVerificationMutation.isLoading}
                          >
                            {executeVerificationMutation.isLoading && executeVerificationMutation.variables?.id === task.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                          </Button>
                          <Button 
                            variant="ghost" 
                            size="icon" 
                            className="hover:bg-zinc-800 text-red-500"
                            title="Delete Task"
                            onClick={() => deleteTaskMutation.mutate({ id: task.id })}
                            disabled={deleteTaskMutation.isLoading && deleteTaskMutation.variables?.id === task.id}
                          >
                             {deleteTaskMutation.isLoading && deleteTaskMutation.variables?.id === task.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
      {selectedTaskId && <VerificationResultsDialog taskId={selectedTaskId} open={!!selectedTaskId} setOpen={() => setSelectedTaskId(null)} />}
    </div>
  );
};

export default RemediationVerification;
