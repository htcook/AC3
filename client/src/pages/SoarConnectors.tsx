import { useState, useEffect, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { PlusCircle, Trash2, Edit, TestTube2, Send, ArrowRightLeft, X } from "lucide-react";

// SOAR Platform type definition
type SoarPlatform = "splunk_soar" | "cortex_xsoar" | "swimlane" | "tines" | "custom";

// Connector type from the backend
type ConnectorFormData = {
  name: string;
  platform: SoarPlatform;
  webhookUrl: string;
  inboundEnabled: boolean;
  outboundEnabled: boolean;
  eventTypes: string;
};

interface SoarEvent {
  id: string;
  connectorId: string;
  direction: 'inbound' | 'outbound';
  eventType: string;
  payload: object;
  status: 'succeeded' | 'failed';
  createdAt: string;
}

interface Connector {
  id: string;
  name: string;
  platform: SoarPlatform;
  webhookUrl: string;
  isActive: boolean;
  inboundEnabled: boolean;
  outboundEnabled: boolean;
  eventTypes: string[];
  createdAt: string;
  updatedAt: string;
}

const platformDisplay: { [key in SoarPlatform]: { name: string; color: string } } = {
  splunk_soar: { name: "Splunk SOAR", color: "bg-blue-500" },
  cortex_xsoar: { name: "Cortex XSOAR", color: "bg-orange-500" },
  swimlane: { name: "Swimlane", color: "bg-purple-500" },
  tines: { name: "Tines", color: "bg-green-500" },
  custom: { name: "Custom", color: "bg-gray-500" },
};

function ConnectorDialog({ open, onOpenChange, connector, onSave }: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  connector: Connector | null;
  onSave: () => void;
}) {
  const [formData, setFormData] = useState<ConnectorFormData>({ name: '', platform: 'custom', webhookUrl: '', inboundEnabled: false, outboundEnabled: false, eventTypes: '' });

  useEffect(() => {
    if (connector) {
      setFormData({
        name: connector.name,
        platform: connector.platform,
        webhookUrl: connector.webhookUrl,
        inboundEnabled: connector.inboundEnabled,
        outboundEnabled: connector.outboundEnabled,
        eventTypes: connector.eventTypes.join(', '),
      });
    } else {
      setFormData({ name: '', platform: 'custom', webhookUrl: '', inboundEnabled: false, outboundEnabled: false, eventTypes: '' });
    }
  }, [connector, open]);

  const createMutation = trpc.soarConnectors.createConnector.useMutation();
  const updateMutation = trpc.soarConnectors.updateConnector.useMutation();

  const handleSave = async () => {
    const eventTypesArray = formData.eventTypes.split(',').map(s => s.trim()).filter(Boolean);
    try {
      if (connector) {
        await updateMutation.mutateAsync({ id: connector.id, ...formData, eventTypes: eventTypesArray });
        toast.success('Connector updated successfully!');
      } else {
        await createMutation.mutateAsync({ ...formData, eventTypes: eventTypesArray });
        toast.success('Connector created successfully!');
      }
      onSave();
      onOpenChange(false);
    } catch (error) {
      toast.error('Failed to save connector.');
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px] bg-slate-900 border-slate-800 text-white">
        <DialogHeader>
          <DialogTitle>{connector ? 'Edit Connector' : 'Create Connector'}</DialogTitle>
          <DialogDescription>
            {connector ? 'Update the details of your SOAR connector.' : 'Configure a new SOAR connector to integrate with your security tools.'}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="name" className="text-right text-slate-300">Name</Label>
            <Input id="name" value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} className="col-span-3 bg-slate-800 border-slate-700" />
          </div>
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="platform" className="text-right text-slate-300">Platform</Label>
            <Select value={formData.platform} onValueChange={(value: SoarPlatform) => setFormData({ ...formData, platform: value })}>
                <SelectTrigger className="col-span-3 bg-slate-800 border-slate-700">
                    <SelectValue placeholder="Select a platform" />
                </SelectTrigger>
                <SelectContent className="bg-slate-900 border-slate-800 text-white">
                    {Object.entries(platformDisplay).map(([key, { name }]) => (
                        <SelectItem key={key} value={key} className="hover:bg-slate-800">{name}</SelectItem>
                    ))}
                </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="webhookUrl" className="text-right text-slate-300">Webhook URL</Label>
            <Input id="webhookUrl" value={formData.webhookUrl} onChange={(e) => setFormData({ ...formData, webhookUrl: e.target.value })} className="col-span-3 bg-slate-800 border-slate-700" />
          </div>
          <div className="grid grid-cols-4 items-center gap-4">
            <Label className="text-right text-slate-300">Event Types</Label>
            <Input id="eventTypes" value={formData.eventTypes} onChange={(e) => setFormData({ ...formData, eventTypes: e.target.value })} placeholder="e.g., alert,incident,task" className="col-span-3 bg-slate-800 border-slate-700" />
          </div>
          <div className="flex items-center justify-around col-span-4 pt-2">
              <div className="flex items-center space-x-2">
                  <input type="checkbox" id="inboundEnabled" checked={formData.inboundEnabled} onChange={(e) => setFormData({ ...formData, inboundEnabled: e.target.checked })} className="form-checkbox h-5 w-5 text-blue-600 bg-slate-800 border-slate-700 rounded focus:ring-blue-500" />
                  <Label htmlFor="inboundEnabled" className="text-slate-300">Inbound</Label>
              </div>
              <div className="flex items-center space-x-2">
                  <input type="checkbox" id="outboundEnabled" checked={formData.outboundEnabled} onChange={(e) => setFormData({ ...formData, outboundEnabled: e.target.checked })} className="form-checkbox h-5 w-5 text-blue-600 bg-slate-800 border-slate-700 rounded focus:ring-blue-500" />
                  <Label htmlFor="outboundEnabled" className="text-slate-300">Outbound</Label>
              </div>
          </div>
        </div>
        <DialogFooter>
          <Button onClick={handleSave} disabled={createMutation.isLoading || updateMutation.isLoading} className="bg-blue-600 hover:bg-blue-700">
            {createMutation.isLoading || updateMutation.isLoading ? 'Saving...' : 'Save changes'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function EventLogTab({ selectedConnector }: { selectedConnector: Connector | null }) {
  const [filter, setFilter] = useState<'all' | 'inbound' | 'outbound'>('all');
  const eventsQuery = trpc.soarConnectors.listEvents.useQuery(
    { connectorId: selectedConnector!.id, direction: filter === 'all' ? undefined : filter },
    { enabled: !!selectedConnector }
  );

  if (!selectedConnector) {
    return <div className="text-center text-slate-400 py-10">Select a connector to view its event log.</div>;
  }

  return (
    <div>
      <div className="flex justify-end mb-4">
        <Select value={filter} onValueChange={(value: 'all' | 'inbound' | 'outbound') => setFilter(value)}>
          <SelectTrigger className="w-[180px] bg-slate-800 border-slate-700">
            <SelectValue placeholder="Filter by direction" />
          </SelectTrigger>
          <SelectContent className="bg-slate-900 border-slate-800 text-white">
            <SelectItem value="all">All Directions</SelectItem>
            <SelectItem value="inbound">Inbound</SelectItem>
            <SelectItem value="outbound">Outbound</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <Table>
        <TableHeader>
          <TableRow className="border-slate-700">
            <TableHead>Timestamp</TableHead>
            <TableHead>Direction</TableHead>
            <TableHead>Event Type</TableHead>
            <TableHead>Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {eventsQuery.isLoading ? (
            <TableRow><TableCell colSpan={4} className="text-center">Loading events...</TableCell></TableRow>
          ) : eventsQuery.data?.length === 0 ? (
            <TableRow><TableCell colSpan={4} className="text-center">No events found.</TableCell></TableRow>
          ) : (
            eventsQuery.data?.map((event: SoarEvent) => (
              <TableRow key={event.id} className="border-slate-800">
                <TableCell>{new Date(event.createdAt).toLocaleString()}</TableCell>
                <TableCell>
                  <Badge variant={event.direction === 'inbound' ? 'outline' : 'secondary'} className={event.direction === 'inbound' ? 'border-green-500 text-green-500' : 'border-blue-500 text-blue-500'}>
                    {event.direction}
                  </Badge>
                </TableCell>
                <TableCell>{event.eventType}</TableCell>
                <TableCell>
                  <Badge variant={event.status === 'succeeded' ? 'default' : 'destructive'} className={event.status === 'succeeded' ? 'bg-green-600' : 'bg-red-600'}>
                    {event.status}
                  </Badge>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}

function ConnectorDetailsTab({ connector, onSendEvent }: { connector: Connector | null, onSendEvent: () => void }) {
  if (!connector) {
    return <div className="text-center text-slate-400 py-10">Select a connector to view its details.</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold">{connector.name}</h3>
        <Button onClick={onSendEvent}><Send className="mr-2 h-4 w-4" /> Send Test Event</Button>
      </div>
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div><strong>ID:</strong> <span className="text-slate-400">{connector.id}</span></div>
        <div><strong>Platform:</strong> <span className="text-slate-400">{platformDisplay[connector.platform].name}</span></div>
        <div><strong>Status:</strong> <span className={connector.isActive ? 'text-green-500' : 'text-red-500'}>{connector.isActive ? 'Active' : 'Inactive'}</span></div>
        <div><strong>Webhook URL:</strong> <span className="text-slate-400">{connector.webhookUrl}</span></div>
        <div><strong>Inbound:</strong> <span className={connector.inboundEnabled ? 'text-green-500' : 'text-slate-400'}>{connector.inboundEnabled ? 'Enabled' : 'Disabled'}</span></div>
        <div><strong>Outbound:</strong> <span className={connector.outboundEnabled ? 'text-blue-500' : 'text-slate-400'}>{connector.outboundEnabled ? 'Enabled' : 'Disabled'}</span></div>
      </div>
      <div>
        <strong>Configured Event Types:</strong>
        <div className="flex flex-wrap gap-2 mt-2">
          {connector.eventTypes.map(et => <Badge key={et} variant="secondary" className="bg-slate-700 text-slate-300">{et}</Badge>)}
        </div>
      </div>
    </div>
  );
}

function SendEventDialog({ open, onOpenChange, connectorId }: { open: boolean, onOpenChange: (open: boolean) => void, connectorId: string | undefined }) {
  const [eventType, setEventType] = useState('');
  const [payload, setPayload] = useState('{}');
  const utils = trpc.useContext();

  const sendEventMutation = trpc.soarConnectors.sendEvent.useMutation({
    onSuccess: () => {
      toast.success('Event sent successfully!');
      utils.soarConnectors.listEvents.invalidate();
      onOpenChange(false);
    },
    onError: (error) => {
      toast.error(`Failed to send event: ${error.message}`);
    }
  });

  const handleSend = () => {
    if (!connectorId) return;
    try {
      const parsedPayload = JSON.parse(payload);
      sendEventMutation.mutate({ connectorId, eventType, payload: parsedPayload });
    } catch (e) {
      toast.error('Invalid JSON payload.');
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg bg-slate-900 border-slate-800 text-white">
        <DialogHeader>
          <DialogTitle>Send Test Event</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="eventType" className="text-right">Event Type</Label>
            <Input id="eventType" value={eventType} onChange={(e) => setEventType(e.target.value)} className="col-span-3 bg-slate-800 border-slate-700" />
          </div>
          <div className="grid grid-cols-4 items-start gap-4">
            <Label htmlFor="payload" className="text-right pt-2">Payload (JSON)</Label>
            <textarea id="payload" value={payload} onChange={(e) => setPayload(e.target.value)} rows={8} className="col-span-3 bg-slate-800 border-slate-700 rounded-md p-2 font-mono text-sm" />
          </div>
        </div>
        <DialogFooter>
          <Button onClick={handleSend} disabled={sendEventMutation.isLoading} className="bg-blue-600 hover:bg-blue-700">
            {sendEventMutation.isLoading ? 'Sending...' : 'Send Event'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function SoarConnectors() {
    const [selectedConnector, setSelectedConnector] = useState<Connector | null>(null);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);
  const [connectorToEdit, setConnectorToEdit] = useState<Connector | null>(null);
    const [connectorToDelete, setConnectorToDelete] = useState<Connector | null>(null);
  const [isTestResultOpen, setIsTestResultOpen] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [isSendEventOpen, setIsSendEventOpen] = useState(false);

    const utils = trpc.useContext();
  const connectorsQuery = trpc.soarConnectors.listConnectors.useQuery();
    const statsQuery = trpc.soarConnectors.getStats.useQuery();
    const testConnectorMutation = trpc.soarConnectors.testConnector.useMutation({
    onSuccess: (data) => {
      setTestResult(data);
      setIsTestResultOpen(true);
    },
    onError: (error) => {
      setTestResult({ success: false, message: error.message });
      setIsTestResultOpen(true);
    },
  });

  const deleteMutation = trpc.soarConnectors.deleteConnector.useMutation({
    onSuccess: () => {
      toast.success('Connector deleted successfully!');
      utils.soarConnectors.listConnectors.invalidate();
      utils.soarConnectors.getStats.invalidate();
      setSelectedConnector(null);
    },
    onError: () => {
      toast.error('Failed to delete connector.');
    },
  });

  const connectors = useMemo(() => connectorsQuery.data ?? [], [connectorsQuery.data]);
  const stats = useMemo(() => statsQuery.data, [statsQuery.data]);
  return (
    <div className="p-4 sm:p-6 lg:p-8 bg-zinc-900 text-white">
      <Card className="bg-slate-900 border-slate-800 mb-6">
        <CardHeader>
          <CardTitle className="flex items-center">
            <ArrowRightLeft className="mr-2 h-6 w-6 text-blue-400" />
            SOAR Connectors
          </CardTitle>
          <CardDescription className="text-slate-400">
            Integrate with Splunk SOAR, Cortex XSOAR, Swimlane, and Tines for automated incident response. Configure inbound/outbound event flows, test webhook connections, send events, and view event history.
          </CardDescription>
        </CardHeader>
      </Card>

      
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-slate-300">Total Connectors</CardTitle>
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" className="h-4 w-4 text-muted-foreground"><path d="M16 22h2a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h2"></path><path d="M12 7v10"></path><path d="M16 12H8"></path></svg>
          </CardHeader>
          <CardContent>
            {statsQuery.isLoading ? (
              <div className="h-8 w-1/2 bg-slate-700 rounded animate-pulse"></div>
            ) : (
              <>
                <div className="text-2xl font-bold">{stats?.totalConnectors ?? 0}</div>
                <p className="text-xs text-muted-foreground text-slate-400">
                  {stats?.activeConnectors ?? 0} active
                </p>
              </>
            )}
          </CardContent>
        </Card>
                <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-slate-300">Inbound Events</CardTitle>
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" className="h-4 w-4 text-muted-foreground"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          </CardHeader>
          <CardContent>
            {statsQuery.isLoading ? (
              <div className="h-8 w-1/2 bg-slate-700 rounded animate-pulse"></div>
            ) : (
              <>
                <div className="text-2xl font-bold">{stats?.inboundEvents ?? 0}</div>
                <p className="text-xs text-muted-foreground text-slate-400">Past 24 hours</p>
              </>
            )}
          </CardContent>
        </Card>
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-slate-300">Outbound Events</CardTitle>
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" className="h-4 w-4 text-muted-foreground"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          </CardHeader>
          <CardContent>
            {statsQuery.isLoading ? (
              <div className="h-8 w-1/2 bg-slate-700 rounded animate-pulse"></div>
            ) : (
              <>
                <div className="text-2xl font-bold">{stats?.outboundEvents ?? 0}</div>
                <p className="text-xs text-muted-foreground text-slate-400">Past 24 hours</p>
              </>
            )}
          </CardContent>
        </Card>
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-slate-300">Error Rate</CardTitle>
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" className="h-4 w-4 text-muted-foreground"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
          </CardHeader>
          <CardContent>
            {statsQuery.isLoading ? (
              <div className="h-8 w-1/2 bg-slate-700 rounded animate-pulse"></div>
            ) : (
              <>
                <div className="text-2xl font-bold">{stats?.errorRate?.toFixed(2) ?? '0.00'}%</div>
                <p className="text-xs text-muted-foreground text-slate-400">Past 24 hours</p>
              </>
            )}
          </CardContent>
        </Card>
      </div>

            <div className="flex justify-end mb-4">
          <Button onClick={() => { setConnectorToEdit(null); setIsDialogOpen(true); }} className="bg-blue-600 hover:bg-blue-700 text-white">
              <PlusCircle className="mr-2 h-4 w-4" /> Create Connector
          </Button>
      </div>

      
      <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
              <CardTitle>Connector List</CardTitle>
          </CardHeader>
          <CardContent>
              <Table>
                  <TableHeader>
                      <TableRow className="border-slate-700">
                          <TableHead>Name</TableHead>
                          <TableHead>Platform</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Inbound</TableHead>
                          <TableHead>Outbound</TableHead>
                          <TableHead>Actions</TableHead>
                      </TableRow>
                  </TableHeader>
                  <TableBody>
                    {connectorsQuery.isLoading ? (
                        <TableRow className="border-slate-800">
                            <TableCell colSpan={6} className="text-center text-slate-400">Loading connectors...</TableCell>
                        </TableRow>
                    ) : connectors.length === 0 ? (
                        <TableRow className="border-slate-800">
                            <TableCell colSpan={6} className="text-center text-slate-400">No connectors configured.</TableCell>
                        </TableRow>
                    ) : (
                        connectors.map((connector) => (
                            <TableRow key={connector.id} className="border-slate-800 hover:bg-slate-800/50 cursor-pointer" onClick={() => setSelectedConnector(connector)}>
                                <TableCell className="font-medium">{connector.name}</TableCell>
                                <TableCell>
                                    <Badge className={`${platformDisplay[connector.platform]?.color} text-white`}>{platformDisplay[connector.platform]?.name}</Badge>
                                </TableCell>
                                <TableCell>
                                    <Badge variant={connector.isActive ? "default" : "destructive"} className={connector.isActive ? "bg-green-600" : "bg-red-600"}>
                                        {connector.isActive ? "Active" : "Inactive"}
                                    </Badge>
                                </TableCell>
                                <TableCell>
                                    <Badge variant={connector.inboundEnabled ? "outline" : "secondary"} className={connector.inboundEnabled ? "border-green-500 text-green-500" : "border-slate-600 text-slate-400"}>
                                        {connector.inboundEnabled ? "Enabled" : "Disabled"}
                                    </Badge>
                                </TableCell>
                                <TableCell>
                                    <Badge variant={connector.outboundEnabled ? "outline" : "secondary"} className={connector.outboundEnabled ? "border-blue-500 text-blue-500" : "border-slate-600 text-slate-400"}>
                                        {connector.outboundEnabled ? "Enabled" : "Disabled"}
                                    </Badge>
                                </TableCell>
                                <TableCell>
                                    <div className="flex items-center space-x-2">
                                                                                <Button variant="ghost" size="icon" className="hover:bg-slate-700" onClick={(e) => { e.stopPropagation(); setConnectorToEdit(connector); setIsDialogOpen(true); }}><Edit className="h-4 w-4" /></Button>
                                                                                <Button variant="ghost" size="icon" className="hover:bg-slate-700" onClick={(e) => { e.stopPropagation(); testConnectorMutation.mutate({ id: connector.id }); }} disabled={testConnectorMutation.isLoading}><TestTube2 className="h-4 w-4" /></Button>
                                                                                <Button variant="ghost" size="icon" className="hover:bg-slate-700 text-red-500" onClick={(e) => { e.stopPropagation(); setConnectorToDelete(connector); setIsDeleteConfirmOpen(true); }}><Trash2 className="h-4 w-4" /></Button>
                                    </div>
                                </TableCell>
                            </TableRow>
                        ))
                    )}
                  </TableBody>
              </Table>
          </CardContent>
      </Card>

            <ConnectorDialog 
        open={isDialogOpen} 
        onOpenChange={setIsDialogOpen} 
        connector={connectorToEdit}
        onSave={() => {
          utils.soarConnectors.listConnectors.invalidate();
          utils.soarConnectors.getStats.invalidate();
        }}
      />

      <Dialog open={isDeleteConfirmOpen} onOpenChange={setIsDeleteConfirmOpen}>
        <DialogContent className="sm:max-w-[425px] bg-slate-900 border-slate-800 text-white">
            <DialogHeader>
                <DialogTitle>Delete Connector</DialogTitle>
                <DialogDescription>
                    Are you sure you want to delete the "{connectorToDelete?.name}" connector? This action cannot be undone.
                </DialogDescription>
            </DialogHeader>
            <DialogFooter>
                <Button variant="outline" onClick={() => setIsDeleteConfirmOpen(false)} className="border-slate-700 hover:bg-slate-800">Cancel</Button>
                <Button variant="destructive" onClick={() => { 
                    if(connectorToDelete) deleteMutation.mutate({ id: connectorToDelete.id });
                    setIsDeleteConfirmOpen(false);
                }} disabled={deleteMutation.isLoading}>
                    {deleteMutation.isLoading ? 'Deleting...' : 'Delete'}
                </Button>
            </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={isTestResultOpen} onOpenChange={setIsTestResultOpen}>
        <DialogContent className="sm:max-w-md bg-slate-900 border-slate-800 text-white">
          <DialogHeader>
            <DialogTitle>Connector Test Result</DialogTitle>
          </DialogHeader>
          <div className="mt-4 space-y-2">
            <p>Status: {testResult?.success ? <Badge className="bg-green-600">Success</Badge> : <Badge variant="destructive">Failed</Badge>}</p>
            <p className="text-sm text-slate-400">{testResult?.message}</p>
          </div>
          <DialogFooter className="sm:justify-start">
            <Button type="button" variant="secondary" onClick={() => setIsTestResultOpen(false)} className="border-slate-700 hover:bg-slate-800">Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <SendEventDialog open={isSendEventOpen} onOpenChange={setIsSendEventOpen} connectorId={selectedConnector?.id} />

      <Tabs defaultValue="events" className="mt-6">
          <TabsList className="grid w-full grid-cols-2 bg-slate-800 text-slate-300">
              <TabsTrigger value="events">Event Log</TabsTrigger>
              <TabsTrigger value="details">Connector Details</TabsTrigger>
          </TabsList>
          <TabsContent value="events" className="bg-slate-900 border-slate-800 p-4 rounded-b-md">
              <EventLogTab selectedConnector={selectedConnector} />
          </TabsContent>
          <TabsContent value="details" className="bg-slate-900 border-slate-800 p-4 rounded-b-md">
              <ConnectorDetailsTab connector={selectedConnector} onSendEvent={() => setIsSendEventOpen(true)} />
          </TabsContent>
      </Tabs>
    </div>
  );
}
