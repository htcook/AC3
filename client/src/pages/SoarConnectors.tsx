"use client";

import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, PlusCircle, AlertTriangle, CheckCircle, XCircle, Send, TestTube } from "lucide-react";
import { useForm, Controller } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { format } from "date-fns";
import AppShell from "@/components/AppShell";

const connectorSchema = z.object({
  name: z.string().min(1, "Name is required"),
  platform: z.enum(['splunk_soar', 'cortex_xsoar', 'swimlane', 'tines', 'custom']),
  webhookUrl: z.string().url("Must be a valid URL"),
  apiKeyEncrypted: z.string().optional(),
  inboundEnabled: z.boolean().default(true),
  outboundEnabled: z.boolean().default(false),
});

type ConnectorFormData = z.infer<typeof connectorSchema>;

const SoarConnectorsPage = () => {
  const [isCreateDialogOpen, setCreateDialogOpen] = useState(false);
  const utils = trpc.useUtils();

  const { data: connectors, isLoading: isLoadingConnectors, error: connectorsError } = trpc.soarConnector.listConnectors.useQuery();

  const createConnectorMutation = trpc.soarConnector.createConnector.useMutation({
    onSuccess: (data) => {
      toast.success(`Connector "${data}" created successfully.`);
      utils.soarConnector.listConnectors.invalidate();
      setCreateDialogOpen(false);
    },
    onError: (error: any) => {
      toast.error("Failed to create connector:", { description: error.message });
    },
  });

  const updateConnectorMutation = trpc.soarConnector.updateConnector.useMutation({
    onSuccess: (data) => {
      toast.success(`Connector "${data}" updated.`);
      utils.soarConnector.listConnectors.invalidate();
    },
    onError: (error: any) => {
      toast.error("Failed to update connector:", { description: error.message });
    },
  });

  const deleteConnectorMutation = trpc.soarConnector.deleteConnector.useMutation({
    onSuccess: () => {
      toast.success("Connector deleted successfully.");
      utils.soarConnector.listConnectors.invalidate();
    },
    onError: (error: any) => {
      toast.error("Failed to delete connector:", { description: error.message });
    },
  });

  const testConnectorMutation = trpc.soarConnector.testConnector.useMutation({
    onMutate: () => {
      const toastId = toast.loading("Testing connector...");
      return { toastId };
    },
    onSuccess: (data, variables, context) => {
      if (data.success) {
        toast.success(`Test successful!`, { id: context?.toastId });
      } else {
        toast.error("Test failed:", { id: context?.toastId, description: data.message });
      }
    },
    onError: (error, variables, context) => {
      toast.error("Failed to test connector:", { id: context?.toastId, description: error.message });
    },
  });

  const { control, handleSubmit, reset, formState: { errors } } = useForm<ConnectorFormData>({
    resolver: zodResolver(connectorSchema) as any,
    defaultValues: {
      name: "",
      platform: "custom",
      webhookUrl: "",
      inboundEnabled: true,
      outboundEnabled: false,
    },
  });

  const handleCreateConnector = (data: any) => {
    createConnectorMutation.mutate(data);
  };

  const handleToggleActive = (id: number, currentStatus: boolean) => {
    updateConnectorMutation.mutate({ id, isActive: !currentStatus });
  };

  return (
    <AppShell activePath="/soar-connectors">
      <div className="p-4 md:p-8 bg-background text-foreground">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>SOAR Connectors</CardTitle>
            <CardDescription>Configure integrations with Security Orchestration, Automation, and Response platforms. Connect to tools like Splunk SOAR, Cortex XSOAR, or Tines to automatically trigger playbooks when findings are discovered, push alerts to incident response workflows, or pull enrichment data back into the platform. Test connector health and review integration logs to ensure reliable automation.</CardDescription>
          </div>
          <Dialog open={isCreateDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button onClick={() => reset()}><PlusCircle className="mr-2 h-4 w-4" /> Create Connector</Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[525px] bg-background text-foreground">
              <form onSubmit={handleSubmit(handleCreateConnector)}>
                <DialogHeader>
                  <DialogTitle>Create New SOAR Connector</DialogTitle>
                  <DialogDescription>Configure a new bidirectional webhook to integrate with a SOAR platform.</DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="name" className="text-right">Name</Label>
                    <Controller name="name" control={control} render={({ field }) => <Input id="name" {...field} className="col-span-3" />} />
                    {errors.name && <p className="col-span-4 text-red-500 text-sm text-right">{errors.name.message}</p>}
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="platform" className="text-right">Platform</Label>
                    <Controller
                      name="platform"
                      control={control}
                      render={({ field }) => (
                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                          <SelectTrigger className="col-span-3">
                            <SelectValue placeholder="Select a platform" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="splunk_soar">Splunk SOAR</SelectItem>
                            <SelectItem value="cortex_xsoar">Cortex XSOAR</SelectItem>
                            <SelectItem value="swimlane">Swimlane</SelectItem>
                            <SelectItem value="tines">Tines</SelectItem>
                            <SelectItem value="custom">Custom</SelectItem>
                          </SelectContent>
                        </Select>
                      )}
                    />
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="webhookUrl" className="text-right">Webhook URL</Label>
                    <Controller name="webhookUrl" control={control} render={({ field }) => <Input id="webhookUrl" {...field} className="col-span-3" />} />
                    {errors.webhookUrl && <p className="col-span-4 text-red-500 text-sm text-right">{errors.webhookUrl.message}</p>}
                  </div>
                   <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="apiKeyEncrypted" className="text-right">API Key</Label>
                    <Controller name="apiKeyEncrypted" control={control} render={({ field }) => <Input id="apiKeyEncrypted" type="password" placeholder="Optional" {...field} className="col-span-3" />} />
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                     <Label htmlFor="inboundEnabled" className="text-right">Inbound</Label>
                     <Controller name="inboundEnabled" control={control} render={({ field }) => <Switch id="inboundEnabled" checked={field.value} onCheckedChange={field.onChange} className="col-span-1" />} />
                  </div>
                   <div className="grid grid-cols-4 items-center gap-4">
                     <Label htmlFor="outboundEnabled" className="text-right">Outbound</Label>
                     <Controller name="outboundEnabled" control={control} render={({ field }) => <Switch id="outboundEnabled" checked={field.value} onCheckedChange={field.onChange} className="col-span-1" />} />
                  </div>
                </div>
                <DialogFooter>
                  <Button type="button" variant="outline" onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
                  <Button type="submit" disabled={createConnectorMutation.isPending}>
                    {createConnectorMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Create
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          {isLoadingConnectors && (
            <div className="flex justify-center items-center h-64">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          )}
          {connectorsError && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{connectorsError.message}</AlertDescription>
            </Alert>
          )}
          {!isLoadingConnectors && !connectorsError && connectors?.length === 0 && (
            <div className="text-center py-16 text-muted-foreground">
              <h3 className="text-lg font-semibold">No Connectors Found</h3>
              <p className="mt-2">Get started by creating a new SOAR connector.</p>
            </div>
          )}
          {!isLoadingConnectors && !connectorsError && connectors && connectors.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Platform</TableHead>
                  <TableHead>Webhook URL</TableHead>
                  <TableHead>Direction</TableHead>
                  <TableHead>Last Event</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {connectors.map((connector) => (
                  <TableRow key={connector.id}>
                    <TableCell>
                       <div className="flex items-center gap-2">
                        <Switch
                          checked={connector.isActive}
                          onCheckedChange={() => handleToggleActive(connector.id, connector.isActive)}
                          disabled={updateConnectorMutation.isPending && updateConnectorMutation.variables?.id === connector.id}
                        />
                        <Badge variant={connector.isActive ? "default" : "outline"} className={connector.isActive ? "bg-green-600" : ""}>
                           {connector.isActive ? "Active" : "Inactive"}
                        </Badge>
                       </div>
                    </TableCell>
                    <TableCell className="font-medium">{connector.name}</TableCell>
                    <TableCell><Badge variant="secondary">{connector.platform}</Badge></TableCell>
                    <TableCell className="text-muted-foreground">{connector.webhookUrl}</TableCell>
                    <TableCell>
                        <div className="flex flex-col gap-1">
                            {connector.inboundEnabled && <Badge variant="outline">Inbound</Badge>}
                            {connector.outboundEnabled && <Badge variant="outline">Outbound</Badge>}
                        </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {connector.createdAt ? format(new Date(connector.createdAt), "PPpp") : "Never"}
                    </TableCell>
                    <TableCell className="text-right space-x-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => testConnectorMutation.mutate({ id: connector.id })}
                        disabled={testConnectorMutation.isPending && testConnectorMutation.variables?.id === connector.id}
                      >
                        <TestTube className="mr-2 h-4 w-4" /> Test
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => deleteConnectorMutation.mutate({ id: connector.id })}
                        disabled={deleteConnectorMutation.isPending && deleteConnectorMutation.variables?.id === connector.id}
                      >
                        <XCircle className="mr-2 h-4 w-4" /> Delete
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

export default SoarConnectorsPage;
