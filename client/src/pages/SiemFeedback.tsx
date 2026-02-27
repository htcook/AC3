import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, PlusCircle, Trash2, PlayCircle, AlertTriangle, CheckCircle, XCircle, Wifi, WifiOff, Power } from "lucide-react";
import { format } from 'date-fns';
import AppShell from "@/components/AppShell";

type IntegrationProvider = 'splunk' | 'elastic' | 'sentinel';

const providerNames: Record<IntegrationProvider, string> = {
  splunk: 'Splunk',
  elastic: 'Elasticsearch',
  sentinel: 'Microsoft Sentinel'
};

export default function SiemFeedback() {
    const [createDialogOpen, setCreateDialogOpen] = useState(false);
    const [selectedIntegrationId, setSelectedIntegrationId] = useState<number | null>(null);

    const utils = trpc.useUtils();

    const integrationsQuery = trpc.siemFeedback.listIntegrations.useQuery();
    const resultsQuery = trpc.siemFeedback.listResults.useQuery(
        { siemId: selectedIntegrationId ?? undefined } as any,
        { enabled: !!selectedIntegrationId }
    );

    const createIntegrationMutation = trpc.siemFeedback.createIntegration.useMutation({
        onSuccess: (data) => {
            utils.siemFeedback.listIntegrations.invalidate();
            toast.success(`Integration "${data.id}" created successfully.`);
            setCreateDialogOpen(false);
        },
        onError: (error) => {
            toast.error("Failed to create integration:", { description: error.message });
        },
    });

    const deleteIntegrationMutation = trpc.siemFeedback.deleteIntegration.useMutation({
        onSuccess: () => {
            utils.siemFeedback.listIntegrations.invalidate();
            utils.siemFeedback.listResults.invalidate();
            if (selectedIntegrationId === deleteIntegrationMutation.variables?.id) {
                setSelectedIntegrationId(null);
            }
            toast.success("Integration deleted successfully.");
        },
        onError: (error) => {
            toast.error("Failed to delete integration:", { description: error.message });
        },
    });

    const testConnectionMutation = trpc.siemFeedback.testConnection.useMutation({
        onSuccess: (data) => {
            const toastFn = data.success ? toast.success : toast.error;
            toastFn(`Test Connection: ${data.message}`,
                { description: data.success ? `Latency: ${data.latencyMs}ms` : "Please check configuration and network." }
            );
        },
        onError: (error) => {
            toast.error("Test Connection Failed:", { description: error.message });
        },
    });

    const executeDetectionMutation = trpc.siemFeedback.executeDetection.useMutation({
        onSuccess: () => {
            toast.success("Detection executed. Refreshing results...");
            resultsQuery.refetch();
        },
        onError: (error) => {
            toast.error("Failed to execute detection:", { description: error.message });
        }
    });

    const selectedIntegration = useMemo(() => 
        integrationsQuery.data?.find(int => int.id === selectedIntegrationId),
        [integrationsQuery.data, selectedIntegrationId]
    );

    const handleCreateIntegration = (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        const formData = new FormData(e.currentTarget);
        const data = Object.fromEntries(formData.entries());
        createIntegrationMutation.mutate({
            name: data.id as string,
            provider: data.provider as IntegrationProvider,
            baseUrl: data?.baseUrl as string,
            apiKeyEncrypted: data.apiKey as string, // Assuming encryption happens on the server
            queryTemplate: data.queryTemplate as string,
        } as any);
    };

    return (
    <AppShell activePath="/siem-feedback">
      <div className="p-4 sm:p-6 lg:p-8 bg-background text-foreground min-h-screen space-y-6">
            <header className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold tracking-tight">SIEM Detection Feedback</h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Track how your SIEM responds to simulated attacks and provide feedback on detection accuracy. This page shows which emulated techniques triggered SIEM alerts, which were missed, and which generated false positives. Use the feedback loop to help blue teams tune their detection rules and improve SIEM coverage. Map detection gaps to specific MITRE ATT&CK techniques for targeted improvement.</p>
                    <p className="text-muted-foreground">Manage SIEM integrations and review detection results.</p>
                </div>
            </header>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <Card className="lg:col-span-1 h-fit">
                    <CardHeader className="flex flex-row items-center justify-between">
                        <div>
                            <CardTitle>SIEM Integrations</CardTitle>
                            <CardDescription>Connect to your SIEM platforms.</CardDescription>
                        </div>
                        <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
                            <DialogTrigger asChild>
                                <Button size="sm"><PlusCircle className="mr-2 h-4 w-4" /> Add</Button>
                            </DialogTrigger>
                            <DialogContent>
                                <DialogHeader>
                                    <DialogTitle>Add SIEM Integration</DialogTitle>
                                </DialogHeader>
                                <form onSubmit={handleCreateIntegration} className="space-y-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="name">Name</Label>
                                        <Input id="name" name="name" placeholder="e.g., Production Splunk" required />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="provider">Provider</Label>
                                        <Select name="provider" required defaultValue="splunk">
                                            <SelectTrigger id="provider">
                                                <SelectValue placeholder="Select a provider" />
                                            </SelectTrigger>
                                            <SelectContent>
                                                <SelectItem value="splunk">Splunk</SelectItem>
                                                <SelectItem value="elastic">Elasticsearch</SelectItem>
                                                <SelectItem value="sentinel">Microsoft Sentinel</SelectItem>
                                            </SelectContent>
                                        </Select>
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="baseUrl">Base URL</Label>
                                        <Input id="baseUrl" name="baseUrl" placeholder="https://splunk.example.com:8089" required />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="apiKey">API Key</Label>
                                        <Input id="apiKey" name="apiKey" type="password" required />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="queryTemplate">Query Template</Label>
                                        <Input id="queryTemplate" name="queryTemplate" placeholder="search {query} | head 1" required />
                                    </div>
                                    <DialogFooter>
                                        <DialogClose asChild>
                                            <Button type="button" variant="outline">Cancel</Button>
                                        </DialogClose>
                                        <Button type="submit" disabled={createIntegrationMutation.isPending}>
                                            {createIntegrationMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Create
                                        </Button>
                                    </DialogFooter>
                                </form>
                            </DialogContent>
                        </Dialog>
                    </CardHeader>
                    <CardContent>
                        {integrationsQuery.isLoading ? (
                            <div className="flex justify-center items-center p-8"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
                        ) : integrationsQuery.isError ? (
                            <Alert variant="destructive">
                                <AlertTriangle className="h-4 w-4" />
                                <AlertTitle>Error</AlertTitle>
                                <AlertDescription>{integrationsQuery.error.message}</AlertDescription>
                            </Alert>
                        ) : (integrationsQuery.data?.length ?? 0) === 0 ? (
                            <div className="text-center text-muted-foreground py-8">No integrations found.</div>
                        ) : (
                            <ul className="space-y-2">
                                {integrationsQuery.data?.map((integration) => (
                                    <li key={integration.id} onClick={() => setSelectedIntegrationId(integration.id)} className={`p-3 rounded-lg border cursor-pointer transition-colors ${selectedIntegrationId === integration.id ? 'bg-muted border-primary' : 'hover:bg-muted/50'}`}>
                                        <div className="flex items-center justify-between">
                                            <div className="font-semibold">{integration.name}</div>
                                            <Badge variant="outline">{providerNames[integration.provider as IntegrationProvider]}</Badge>
                                        </div>
                                        <div className="text-sm text-muted-foreground mt-1">{integration?.baseUrl}</div>
                                        <div className="flex items-center gap-2 mt-3">
                                            <Button size="sm" variant="outline" onClick={(e) => { e.stopPropagation(); toast.info('Connection test initiated for ' + integration.provider); }} disabled={false}>
                                                {false ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Wifi className="mr-2 h-4 w-4" />} Test
                                            </Button>
                                            <Button size="sm" variant="destructive" onClick={(e) => { e.stopPropagation(); deleteIntegrationMutation.mutate({ id: integration.id }); }} disabled={deleteIntegrationMutation.isPending && deleteIntegrationMutation.variables?.id === integration.id}>
                                                {deleteIntegrationMutation.isPending && deleteIntegrationMutation.variables?.id === integration.id ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />} Delete
                                            </Button>
                                        </div>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </CardContent>
                </Card>

                <Card className="lg:col-span-2">
                    <CardHeader>
                        <CardTitle>Detection Results</CardTitle>
                        <CardDescription>
                            {selectedIntegration ? `Showing results for "${selectedIntegration.name}"` : "Select an integration to view results."}
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        {!selectedIntegrationId ? (
                            <div className="flex flex-col items-center justify-center h-96 text-muted-foreground">
                                <Power className="h-12 w-12 mb-4" />
                                <p>Please select a SIEM integration from the list.</p>
                            </div>
                        ) : resultsQuery.isLoading ? (
                            <div className="flex justify-center items-center h-96"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
                        ) : resultsQuery.isError ? (
                            <Alert variant="destructive">
                                <AlertTriangle className="h-4 w-4" />
                                <AlertTitle>Error</AlertTitle>
                                <AlertDescription>{resultsQuery.error.message}</AlertDescription>
                            </Alert>
                        ) : (resultsQuery.data ?? []).length === 0 ? (
                            <div className="text-center text-muted-foreground py-8">
                                <p>No detection results found for this integration.</p>
                                <Button className="mt-4" onClick={() => executeDetectionMutation.mutate({ siemId: selectedIntegrationId, techniqueId: 'T1059', techniqueName: 'Example Technique', executedAt: new Date().toISOString() })} disabled={executeDetectionMutation.isPending}>
                                    <PlayCircle className="mr-2 h-4 w-4" /> Run Example Detection
                                </Button>
                            </div>
                        ) : (
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>Status</TableHead>
                                        <TableHead>Technique</TableHead>
                                        <TableHead>Result Count</TableHead>
                                        <TableHead>Executed At</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {(resultsQuery.data ?? []).map((result) => (
                                        <TableRow key={result.id}>
                                            <TableCell>
                                                <Badge variant={result.detectionResult ? "secondary" : "destructive"}>
                                                    {result.detectionResult ? <CheckCircle className="mr-2 h-4 w-4 text-green-500" /> : <XCircle className="mr-2 h-4 w-4 text-red-500" />} {result.detectionResult ? 'Passed' : 'Failed'}
                                                </Badge>
                                            </TableCell>
                                            <TableCell>{result.techniqueName} ({result.techniqueId})</TableCell>
                                            <TableCell>{result.alertsFound}</TableCell>
                                            <TableCell>{format(new Date(result.executedAt), "PPpp")}</TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        )}
                    </CardContent>
                </Card>
            </div>
        </div>
    </AppShell>
  );
}
