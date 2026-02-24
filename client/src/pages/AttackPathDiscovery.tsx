
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useState } from "react";
import { useForm, Controller } from "react-hook-form";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";

interface Node {
  id: number;
  nodeType: string;
  name: string;
  properties: string | null;
  riskScore: number | null;
  isCrownJewel: boolean | null;
  source: string | null;
  createdAt: Date;
}

const AddNodeForm = ({ onNodeAdded }: { onNodeAdded: () => void }) => {
  const utils = trpc.useUtils();
  const { register, handleSubmit, control, reset, formState: { errors } } = useForm<{
    nodeType: 'user'|'computer'|'group'|'service'|'cloud_identity'|'vulnerability'|'crown_jewel';
    name: string;
    properties?: string;
    riskScore?: number;
    isCrownJewel?: boolean;
    source?: string;
  }>();

  const addNodeMutation = trpc.attackPathDiscovery.addNode.useMutation({
    onSuccess: () => {
      toast.success("Node added successfully!");
      utils.attackPathDiscovery.listNodes.invalidate();
      reset();
      onNodeAdded();
    },
    onError: (error: any) => {
      toast.error(`Failed to add node: ${error.message}`);
    },
  });

  const onSubmit = (data: any) => {
    addNodeMutation.mutate(data);
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      <Input placeholder="Name" {...register("name", { required: true })} />
      {errors.name && <span className="text-red-500">Name is required</span>}
      <Controller
        name="nodeType"
        control={control}
        rules={{ required: true }}
        render={({ field }) => (
          <Select onValueChange={field.onChange} defaultValue={field.value}>
            <SelectTrigger>
              <SelectValue placeholder="Node Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="user">User</SelectItem>
              <SelectItem value="computer">Computer</SelectItem>
              <SelectItem value="group">Group</SelectItem>
              <SelectItem value="service">Service</SelectItem>
              <SelectItem value="cloud_identity">Cloud Identity</SelectItem>
              <SelectItem value="vulnerability">Vulnerability</SelectItem>
              <SelectItem value="crown_jewel">Crown Jewel</SelectItem>
            </SelectContent>
          </Select>
        )}
      />
      {errors.nodeType && <span className="text-red-500">Node type is required</span>}
      <Input placeholder="Properties (JSON)" {...register("properties")} />
      <Input type="number" placeholder="Risk Score" {...register("riskScore", { valueAsNumber: true })} />
      <div className="flex items-center space-x-2">
        <input type="checkbox" {...register("isCrownJewel")} id="isCrownJewel" />
        <label htmlFor="isCrownJewel">Is Crown Jewel?</label>
      </div>
      <Input placeholder="Source" {...register("source")} />
      <Button type="submit" disabled={addNodeMutation.isPending}>
        {addNodeMutation.isPending ? "Adding..." : "Add Node"}
      </Button>
    </form>
  );
};

const AddEdgeForm = ({ nodes, onEdgeAdded }: { nodes: Node[], onEdgeAdded: () => void }) => {
    const utils = trpc.useUtils();
    const { register, handleSubmit, control, reset, formState: { errors } } = useForm<{
        sourceNodeId: number;
        targetNodeId: number;
        edgeType: string;
        technique?: string;
        probability?: number;
    }>();

    const addEdgeMutation = trpc.attackPathDiscovery.addEdge.useMutation({
        onSuccess: () => {
            toast.success("Edge added successfully!");
            utils.attackPathDiscovery.listNodes.invalidate();
            reset();
            onEdgeAdded();
        },
        onError: (error: any) => {
            toast.error(`Failed to add edge: ${error.message}`);
        },
    });

    const onSubmit = (data: any) => {
        addEdgeMutation.mutate(data);
    };

    return (
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <Controller
                name="sourceNodeId"
                control={control}
                rules={{ required: true }}
                render={({ field }) => (
                    <Select onValueChange={(v: any) => field.onChange(parseInt(v))} >
                        <SelectTrigger><SelectValue placeholder="Source Node" /></SelectTrigger>
                        <SelectContent>
                            {nodes.map(node => <SelectItem key={node.id} value={String(node.id)}>{node.name}</SelectItem>)}
                        </SelectContent>
                    </Select>
                )}
            />
            {errors.sourceNodeId && <span className="text-red-500">Source node is required</span>}

            <Controller
                name="targetNodeId"
                control={control}
                rules={{ required: true }}
                render={({ field }) => (
                    <Select onValueChange={(v: any) => field.onChange(parseInt(v))} >
                        <SelectTrigger><SelectValue placeholder="Target Node" /></SelectTrigger>
                        <SelectContent>
                            {nodes.map(node => <SelectItem key={node.id} value={String(node.id)}>{node.name}</SelectItem>)}
                        </SelectContent>
                    </Select>
                )}
            />
            {errors.targetNodeId && <span className="text-red-500">Target node is required</span>}

            <Input placeholder="Edge Type" {...register("edgeType", { required: true })} />
            {errors.edgeType && <span className="text-red-500">Edge type is required</span>}

            <Input placeholder="Technique" {...register("technique")} />
            <Input type="number" step="0.01" placeholder="Probability" {...register("probability", { valueAsNumber: true })} />

            <Button type="submit" disabled={addEdgeMutation.isPending}>
                {addEdgeMutation.isPending ? "Adding..." : "Add Edge"}
            </Button>
        </form>
    );
};


export default function AttackPathDiscoveryPage() {
  const [isAddNodeOpen, setIsAddNodeOpen] = useState(false);
  const [isAddEdgeOpen, setIsAddEdgeOpen] = useState(false);
  const [maxHops, setMaxHops] = useState<number>(5);
  const [maxPaths, setMaxPaths] = useState<number>(10);

  const { data: nodes, isLoading, isError, error } = trpc.attackPathDiscovery.listNodes.useQuery();
  const discoverPathsMutation = trpc.attackPathDiscovery.discoverPaths.useMutation({
    onSuccess: (data) => {
        if (data.paths.length === 0) {
            toast.info("No attack paths found with the given parameters.");
        } else {
            toast.success(`${data.discovered} attack paths discovered!`);
        }
    },
    onError: (error: any) => {
        toast.error(`Failed to discover paths: ${error.message}`);
    }
  });

  const handleDiscoverPaths = () => {
    discoverPathsMutation.mutate({ maxHops, maxPaths });
  }

  if (isLoading) {
    return <div className="flex items-center justify-center h-screen bg-background text-foreground">Loading...</div>;
  }

  if (isError) {
    return <div className="flex items-center justify-center h-screen bg-background text-red-500">Error: {error.message}</div>;
  }

  return (
    <AppShell activePath="/attack-path-discovery">
      <div className="p-8 bg-background text-foreground min-h-screen">
      <header className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold">Attack Path Discovery</h1>
        <div className="space-x-2">
            <Dialog open={isAddNodeOpen} onOpenChange={setIsAddNodeOpen}>
                <DialogTrigger asChild>
                    <Button>Add Node</Button>
                </DialogTrigger>
                <DialogContent>
                    <DialogHeader><DialogTitle>Add New Node</DialogTitle></DialogHeader>
                    <AddNodeForm onNodeAdded={() => setIsAddNodeOpen(false)} />
                </DialogContent>
            </Dialog>
            <Dialog open={isAddEdgeOpen} onOpenChange={setIsAddEdgeOpen}>
                <DialogTrigger asChild>
                    <Button>Add Edge</Button>
                </DialogTrigger>
                <DialogContent>
                    <DialogHeader><DialogTitle>Add New Edge</DialogTitle></DialogHeader>
                    <AddEdgeForm nodes={(nodes || []) as any} onEdgeAdded={() => setIsAddEdgeOpen(false)} />
                </DialogContent>
            </Dialog>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        <Card className="col-span-1 md:col-span-2">
          <CardHeader>
            <CardTitle>Graph Nodes</CardTitle>
          </CardHeader>
          <CardContent>
            {nodes && nodes.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Risk Score</TableHead>
                    <TableHead>Crown Jewel</TableHead>
                    <TableHead>Source</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {nodes.map((node) => (
                    <TableRow key={node.id}>
                      <TableCell>{node.name}</TableCell>
                      <TableCell><Badge variant="outline">{node.nodeType}</Badge></TableCell>
                      <TableCell>{node.riskScore ?? 'N/A'}</TableCell>
                      <TableCell>{node.isCrownJewel ? <Badge>Yes</Badge> : 'No'}</TableCell>
                      <TableCell>{node.source ?? 'N/A'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p>No nodes found. Add nodes to begin.</p>
            )}
          </CardContent>
        </Card>

        <div className="space-y-8">
            <Card>
                <CardHeader><CardTitle>Discovery Engine</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                    <div>
                        <label htmlFor="maxHops" className="block text-sm font-medium mb-1">Max Hops</label>
                        <Input id="maxHops" type="number" value={maxHops} onChange={(e: any) => setMaxHops(parseInt(e.target.value))} />
                    </div>
                    <div>
                        <label htmlFor="maxPaths" className="block text-sm font-medium mb-1">Max Paths</label>
                        <Input id="maxPaths" type="number" value={maxPaths} onChange={(e: any) => setMaxPaths(parseInt(e.target.value))} />
                    </div>
                    <Button onClick={handleDiscoverPaths} disabled={discoverPathsMutation.isPending} className="w-full">
                        {discoverPathsMutation.isPending ? 'Discovering...' : 'Discover Attack Paths'}
                    </Button>
                </CardContent>
            </Card>

            <Card>
                <CardHeader><CardTitle>Discovered Paths</CardTitle></CardHeader>
                <CardContent>
                    {discoverPathsMutation.isPending && <p>Searching for paths...</p>}
                    {discoverPathsMutation.isError && <p className="text-red-500">Error: {discoverPathsMutation.error.message}</p>}
                    {discoverPathsMutation.data && (
                        discoverPathsMutation.data.paths.length > 0 ? (
                            <ul className="space-y-2">
                                {discoverPathsMutation.data.paths.map((path: any, index: number) => {
                                    // FIX: pathNodes may be a JSON string or an array of node IDs (numbers)
                                    let pathNodeDisplay: string;
                                    try {
                                      const pathNodes = typeof path.pathNodes === "string"
                                        ? JSON.parse(path.pathNodes)
                                        : (path.nodes || path.pathNodes || []);
                                      pathNodeDisplay = Array.isArray(pathNodes)
                                        ? pathNodes.join(" → ")
                                        : String(pathNodes);
                                    } catch {
                                      pathNodeDisplay = path.name || `Path ${index + 1}`;
                                    }
                                    return (
                                      <li key={index} className="p-2 border rounded-md">
                                          <p className="font-semibold">{path.name}</p>
                                          <p className="text-sm text-gray-400">{pathNodeDisplay}</p>
                                          {path.riskScore != null && (
                                            <p className="text-xs text-muted-foreground mt-1">
                                              Risk: {path.riskScore} · Hops: {path.totalHops ?? path.nodes?.length ?? 0}
                                            </p>
                                          )}
                                      </li>
                                    );
                                })}
                            </ul>
                        ) : (
                           !discoverPathsMutation.isPending && <p>No paths found.</p>
                        )
                    )}
                     {!discoverPathsMutation.data && !discoverPathsMutation.isPending && <p>Run discovery to see paths.</p>}
                </CardContent>
            </Card>
        </div>
      </div>
    </div>
    </AppShell>
  );
}
