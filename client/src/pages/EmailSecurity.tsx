
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, PlusCircle, AlertCircle, Trash2, PlayCircle } from "lucide-react";
import AppShell from "@/components/AppShell";

type GatewayType = 'proofpoint' | 'mimecast' | 'defender' | 'barracuda' | 'custom';
type PayloadType = 'phishing_link' | 'malware_attachment' | 'credential_harvest' | 'bec_impersonation' | 'custom';
type Status = 'pending' | 'running' | 'completed' | 'failed';

const statusColors: Record<Status, string> = {
  pending: "bg-yellow-500",
  running: "bg-blue-500",
  completed: "bg-green-500",
  failed: "bg-red-500",
};

const CreateTestForm = ({ setOpen }: { setOpen: (open: boolean) => void }) => {
  const utils = trpc.useUtils();
  const [name, setName] = useState("");
  const [targetEmail, setTargetEmail] = useState("");
  const [gatewayType, setGatewayType] = useState<any>('proofpoint');
  const [payloadType, setPayloadType] = useState<any>('phishing_link');

  const createTestMutation = trpc.emailSecurity.create.useMutation({
    onSuccess: () => {
      toast.success("Email security test created successfully.");
      utils.emailSecurity.list.invalidate();
      setOpen(false);
    },
    onError: (error: any) => {
      toast.error("Failed to create test: " + error.message);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createTestMutation.mutate({ name, gatewayType, targetEmail, payloadType });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <Input placeholder="Test Name" value={name} onChange={(e) => setName(e.target.value)} required />
      <Input placeholder="Target Email" type="email" value={targetEmail} onChange={(e) => setTargetEmail(e.target.value)} required />
      <Select onValueChange={(value: GatewayType) => setGatewayType(value)} value={gatewayType}>
        <SelectTrigger><SelectValue placeholder="Select Gateway Type" /></SelectTrigger>
        <SelectContent>
          <SelectItem value="proofpoint">Proofpoint</SelectItem>
          <SelectItem value="mimecast">Mimecast</SelectItem>
          <SelectItem value="defender">Defender</SelectItem>
          <SelectItem value="barracuda">Barracuda</SelectItem>
          <SelectItem value="custom">Custom</SelectItem>
        </SelectContent>
      </Select>
      <Select onValueChange={(value: PayloadType) => setPayloadType(value)} value={payloadType}>
        <SelectTrigger><SelectValue placeholder="Select Payload Type" /></SelectTrigger>
        <SelectContent>
          <SelectItem value="phishing_link">Phishing Link</SelectItem>
          <SelectItem value="malware_attachment">Malware Attachment</SelectItem>
          <SelectItem value="credential_harvest">Credential Harvest</SelectItem>
          <SelectItem value="bec_impersonation">BEC Impersonation</SelectItem>
          <SelectItem value="custom">Custom</SelectItem>
        </SelectContent>
      </Select>
      <Button type="submit" disabled={createTestMutation.isPending} className="w-full">
        {createTestMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
        Create Test
      </Button>
    </form>
  );
};

const EmailSecurityPage = () => {
  const [isCreateOpen, setCreateOpen] = useState(false);
  const [filters, setFilters] = useState<{ gatewayType?: GatewayType, status?: Status }>({});

  const { data: tests, isLoading, isError, error } = trpc.emailSecurity.list.useQuery(filters as any);
  const { data: stats } = trpc.emailSecurity.getStats.useQuery();
  const utils = trpc.useUtils();

  const executeMutation = trpc.emailSecurity.execute.useMutation({
    onSuccess: () => {
      toast.success("Test execution started.");
      utils.emailSecurity.list.invalidate();
    },
    onError: (error: any) => {
      toast.error("Failed to execute test: " + error.message);
    },
  });

  const deleteMutation = trpc.emailSecurity.delete.useMutation({
    onSuccess: () => {
      toast.success("Test deleted successfully.");
      utils.emailSecurity.list.invalidate();
    },
    onError: (error: any) => {
      toast.error("Failed to delete test: " + error.message);
    },
  });

  const handleExecute = (id: number) => {
    executeMutation.mutate({ id });
  };

  const handleDelete = (id: number) => {
    if (window.confirm("Are you sure you want to delete this test?")) {
      deleteMutation.mutate({ id });
    }
  };

  return (
    <AppShell activePath="/email-security">
      <div className="min-h-screen bg-background text-foreground p-8">
      <header className="flex items-center justify-between mb-8">
        <h1 className="text-3xl font-bold">Email Security Gateway Validation</h1>
        <Dialog open={isCreateOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button><PlusCircle className="mr-2 h-4 w-4" /> Create Test</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create New Email Security Test</DialogTitle>
            </DialogHeader>
            <CreateTestForm setOpen={setCreateOpen} />
          </DialogContent>
        </Dialog>
      </header>

      <section className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <Card>
          <CardHeader><CardTitle>Total Tests</CardTitle></CardHeader>
          <CardContent><p className="text-3xl font-bold">{Array.isArray(stats) ? stats.reduce((a: number, s: any) => a + (s.total || 0), 0) : (stats as any)?.total ?? '...'}</p></CardContent>
        </Card>
        {/* Add more stat cards as needed */}
      </section>

      <Card>
        <CardHeader>
          <CardTitle>Test Runs</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading && (
            <div className="flex justify-center items-center p-8">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          )}
          {isError && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error.message}</AlertDescription>
            </Alert>
          )}
          {!isLoading && !isError && tests && tests.length === 0 && (
            <div className="text-center p-8">
              <p className="text-muted-foreground">No email security tests found. Get started by creating one.</p>
            </div>
          )}
          {!isLoading && !isError && tests && tests.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Gateway</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Payload</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Executed At</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tests.map((test) => (
                  <TableRow key={test.id}>
                    <TableCell className="font-medium">{test.name}</TableCell>
                    <TableCell><Badge variant="secondary">{test.gatewayType}</Badge></TableCell>
                    <TableCell>{test.targetEmail}</TableCell>
                    <TableCell>{test.payloadType.replace(/_/g, ' ')}</TableCell>
                    <TableCell>
                      <div className="flex items-center">
                        <span className={`h-2 w-2 rounded-full mr-2 ${statusColors[test.status as Status]}`}></span>
                        {test.status}
                      </div>
                    </TableCell>
                    <TableCell>{test.createdAt ? new Date(test.createdAt).toLocaleString() : 'N/A'}</TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" onClick={() => handleExecute(test.id)} disabled={executeMutation.isPending && executeMutation.variables?.id === test.id}>
                        <PlayCircle className="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="icon" onClick={() => handleDelete(test.id)} disabled={deleteMutation.isPending && deleteMutation.variables?.id === test.id}>
                        <Trash2 className="h-4 w-4 text-red-500" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
    </AppShell>
  );
};

export default EmailSecurityPage;
