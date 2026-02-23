import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { PlusCircle, Zap, Shield, AlertTriangle, Network, Target, Waypoints, GitBranch, CheckCircle, XCircle, Hourglass, Server, User, Group, Key, Cloud, Bug } from "lucide-react";

// Mock data types - replace with your actual generated types
type Node = {
  id: string;
  name: string;
  nodeType: string;
  riskScore?: number;
  isCrownJewel?: boolean;
};

type DiscoveredPath = {
  id: string;
  nodes: Node[];
  riskScore: number;
  hopCount: number;
  status: 'active' | 'mitigated' | 'accepted';
};

const nodeTypeIcons = {
    user: <User className="h-4 w-4" />,
    computer: <Server className="h-4 w-4" />,
    group: <Group className="h-4 w-4" />,
    service: <Key className="h-4 w-4" />,
    cloud_identity: <Cloud className="h-4 w-4" />,
    vulnerability: <Bug className="h-4 w-4" />,
    crown_jewel: <Target className="h-4 w-4 text-yellow-400" />,
};

const AddNodeDialog = ({ onNodeAdded }: { onNodeAdded: () => void }) => {
    const [nodeType, setNodeType] = useState('user');
    const [name, setName] = useState('');
    const [riskScore, setRiskScore] = useState('');
    const [isCrownJewel, setIsCrownJewel] = useState(false);
    const [open, setOpen] = useState(false);

    const addNodeMutation = trpc.attackPathDiscovery.addNode.useMutation({
        onSuccess: () => {
            toast.success("Node added successfully");
            onNodeAdded();
            setOpen(false);
            setName('');
            setRiskScore('');
            setIsCrownJewel(false);
        },
        onError: (error) => {
            toast.error(`Failed to add node: ${error.message}`);
        },
    });

    const handleSubmit = () => {
        addNodeMutation.mutate({ 
            nodeType: nodeType as any, 
            name, 
            riskScore: riskScore ? parseInt(riskScore) : undefined, 
            isCrownJewel 
        });
    };

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                <Button variant="outline" className="bg-zinc-700 border-zinc-600 hover:bg-zinc-600">
                    <PlusCircle className="mr-2 h-4 w-4" /> Add Node
                </Button>
            </DialogTrigger>
            <DialogContent className="bg-zinc-800 border-zinc-700 text-gray-200">
                <DialogHeader>
                    <DialogTitle>Add New Asset Node</DialogTitle>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="name" className="text-right">Name</Label>
                        <Input id="name" value={name} onChange={(e) => setName(e.target.value)} className="col-span-3 bg-zinc-700 border-zinc-600" />
                    </div>
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="nodeType" className="text-right">Type</Label>
                        <Select value={nodeType} onValueChange={setNodeType}>
                            <SelectTrigger className="col-span-3 bg-zinc-700 border-zinc-600">
                                <SelectValue placeholder="Select node type" />
                            </SelectTrigger>
                            <SelectContent className="bg-zinc-800 border-zinc-700 text-gray-200">
                                {Object.keys(nodeTypeIcons).map(type => (
                                    <SelectItem key={type} value={type}>{type.charAt(0).toUpperCase() + type.slice(1).replace('_', ' ')}</SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="riskScore" className="text-right">Risk Score</Label>
                        <Input id="riskScore" type="number" value={riskScore} onChange={(e) => setRiskScore(e.target.value)} className="col-span-3 bg-zinc-700 border-zinc-600" />
                    </div>
                     <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="isCrownJewel" className="text-right">Crown Jewel</Label>
                        <div className="col-span-3 flex items-center">
                            <input type="checkbox" id="isCrownJewel" checked={isCrownJewel} onChange={(e) => setIsCrownJewel(e.target.checked)} className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500" />
                        </div>
                    </div>
                </div>
                <Button onClick={handleSubmit} disabled={addNodeMutation.isLoading} className="w-full bg-blue-600 hover:bg-blue-700">
                    {addNodeMutation.isLoading ? "Adding..." : "Add Node"}
                </Button>
            </DialogContent>
        </Dialog>
    );
};

const AttackPathDiscoveryPage = () => {
    const utils = trpc.useContext();
    const { data: stats, isLoading: statsLoading } = trpc.attackPathDiscovery.getStats.useQuery();
    const { data: nodes, isLoading: nodesLoading, refetch: refetchNodes } = trpc.attackPathDiscovery.listNodes.useQuery();
    const { data: discoveredPaths, isLoading: pathsLoading, refetch: refetchPaths } = trpc.attackPathDiscovery.listDiscoveredPaths.useQuery({});

    const discoverPathsMutation = trpc.attackPathDiscovery.discoverPaths.useMutation({
        onSuccess: () => {
            toast.success("Attack path discovery initiated!");
            refetchPaths();
        },
        onError: (error) => {
            toast.error(`Discovery failed: ${error.message}`);
        },
    });

    const updatePathStatusMutation = trpc.attackPathDiscovery.updatePathStatus.useMutation({
        onSuccess: () => {
            toast.success("Path status updated.");
            utils.attackPathDiscovery.listDiscoveredPaths.invalidate();
        },
        onError: (error) => {
            toast.error(`Update failed: ${error.message}`);
        }
    });

    const onNodeAdded = useCallback(() => {
        refetchNodes();
        utils.attackPathDiscovery.getStats.invalidate();
    }, [refetchNodes, utils]);

    const handleDiscoverPaths = () => {
        discoverPathsMutation.mutate({ maxHops: 5, maxPaths: 10 });
    };

    const handleStatusChange = (id: string, status: 'active' | 'mitigated' | 'accepted') => {
        updatePathStatusMutation.mutate({ id, status });
    };

    const statusBadge = (status: 'active' | 'mitigated' | 'accepted') => {
        switch (status) {
            case 'active': return <Badge variant="destructive">Active</Badge>;
            case 'mitigated': return <Badge className="bg-green-600">Mitigated</Badge>;
            case 'accepted': return <Badge variant="secondary">Accepted</Badge>;
        }
    };

    return (
        <div className="flex flex-col h-full p-4 md:p-6 bg-zinc-900 text-gray-200">
            <Card className="mb-6 bg-zinc-800 border-zinc-700">
                <CardHeader>
                    <CardTitle className="text-xl text-gray-100">Attack Path Discovery</CardTitle>
                </CardHeader>
                <CardContent>
                    <p className="text-gray-400">
                        Automated attack path discovery engine. Build an asset graph with nodes and edges, then run the discovery algorithm to find attack paths to critical assets.
                    </p>
                </CardContent>
            </Card>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
                {statsLoading ? Array.from({ length: 4 }).map((_, i) => <Card key={i} className="bg-zinc-800 border-zinc-700"><CardHeader><div className="h-4 w-3/4 bg-zinc-700 animate-pulse rounded-md" /></CardHeader><CardContent><div className="h-8 w-1/2 bg-zinc-700 animate-pulse rounded-md" /></CardContent></Card>) :
                    <>
                        <Card className="bg-zinc-800 border-zinc-700">
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium text-gray-400">Total Nodes</CardTitle><Network className="h-4 w-4 text-gray-500" /></CardHeader>
                            <CardContent><div className="text-2xl font-bold text-gray-100">{stats?.totalNodes ?? 0}</div></CardContent>
                        </Card>
                        <Card className="bg-zinc-800 border-zinc-700">
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium text-gray-400">Crown Jewels</CardTitle><Target className="h-4 w-4 text-yellow-400" /></CardHeader>
                            <CardContent><div className="text-2xl font-bold text-gray-100">{stats?.crownJewels ?? 0}</div></CardContent>
                        </Card>
                        <Card className="bg-zinc-800 border-zinc-700">
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium text-gray-400">Discovered Paths</CardTitle><Waypoints className="h-4 w-4 text-gray-500" /></CardHeader>
                            <CardContent><div className="text-2xl font-bold text-gray-100">{stats?.discoveredPaths ?? 0}</div></CardContent>
                        </Card>
                        <Card className="bg-zinc-800 border-zinc-700">
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium text-gray-400">Avg. Risk Score</CardTitle><AlertTriangle className="h-4 w-4 text-red-500" /></CardHeader>
                            <CardContent><div className="text-2xl font-bold text-gray-100">{stats?.avgRiskScore?.toFixed(2) ?? 'N/A'}</div></CardContent>
                        </Card>
                    </>
                }
            </div>

            <Tabs defaultValue="paths" className="flex-grow flex flex-col">
                <div className="flex justify-between items-center mb-4">
                    <TabsList className="bg-zinc-800 border-zinc-700">
                        <TabsTrigger value="paths">Discovered Paths</TabsTrigger>
                        <TabsTrigger value="graph">Asset Graph</TabsTrigger>
                    </TabsList>
                    <div className="flex gap-2">
                         <AddNodeDialog onNodeAdded={onNodeAdded} />
                        <Button onClick={handleDiscoverPaths} disabled={discoverPathsMutation.isLoading} className="bg-green-600 hover:bg-green-700">
                            <Zap className="mr-2 h-4 w-4" /> {discoverPathsMutation.isLoading ? "Discovering..." : "Discover Paths"}
                        </Button>
                    </div>
                </div>
                <TabsContent value="paths" className="flex-grow rounded-lg bg-zinc-800 border border-zinc-700 p-4">
                    {pathsLoading ? <div className="flex items-center justify-center h-full"><Hourglass className="h-8 w-8 animate-spin" /></div> :
                        !discoveredPaths || discoveredPaths.length === 0 ? <div className="text-center text-gray-500">No attack paths discovered yet.</div> :
                        <Table>
                            <TableHeader>
                                <TableRow className="border-zinc-700 hover:bg-zinc-700/50">
                                    <TableHead className="text-gray-300">Path</TableHead>
                                    <TableHead className="text-gray-300">Risk Score</TableHead>
                                    <TableHead className="text-gray-300">Hop Count</TableHead>
                                    <TableHead className="text-gray-300">Status</TableHead>
                                    <TableHead className="text-right text-gray-300">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {discoveredPaths.map((path: DiscoveredPath) => (
                                    <TableRow key={path.id} className="border-zinc-700 hover:bg-zinc-700/50">
                                        <TableCell className="font-medium flex items-center gap-2 flex-wrap">
                                            {path.nodes.map((node, i) => <span key={node.id} className="flex items-center">{nodeTypeIcons[node.nodeType as keyof typeof nodeTypeIcons]}<span className="ml-1">{node.name}</span> {i < path.nodes.length - 1 && <GitBranch className="h-4 w-4 mx-1 text-zinc-500" />}</span>)}
                                        </TableCell>
                                        <TableCell><Progress value={path.riskScore} className="w-24" indicatorClassName={path.riskScore > 70 ? "bg-red-500" : path.riskScore > 40 ? "bg-yellow-500" : "bg-green-500"} /></TableCell>
                                        <TableCell>{path.hopCount}</TableCell>
                                        <TableCell>{statusBadge(path.status)}</TableCell>
                                        <TableCell className="text-right">
                                            <Select onValueChange={(status) => handleStatusChange(path.id, status as any)} defaultValue={path.status}>
                                                <SelectTrigger className="w-[120px] bg-zinc-700 border-zinc-600">
                                                    <SelectValue placeholder="Update..." />
                                                </SelectTrigger>
                                                <SelectContent className="bg-zinc-800 border-zinc-700 text-gray-200">
                                                    <SelectItem value="mitigated"><CheckCircle className="h-4 w-4 mr-2 inline" />Mitigate</SelectItem>
                                                    <SelectItem value="accepted"><XCircle className="h-4 w-4 mr-2 inline" />Accept</SelectItem>
                                                </SelectContent>
                                            </Select>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    }
                </TabsContent>
                <TabsContent value="graph" className="flex-grow rounded-lg bg-zinc-800 border border-zinc-700 p-4">
                     {nodesLoading ? <div className="flex items-center justify-center h-full"><Hourglass className="h-8 w-8 animate-spin" /></div> :
                        !nodes || nodes.length === 0 ? <div className="text-center text-gray-500">No nodes in the graph. Add one to get started.</div> :
                        <Table>
                            <TableHeader>
                                <TableRow className="border-zinc-700 hover:bg-zinc-700/50">
                                    <TableHead className="text-gray-300">Name</TableHead>
                                    <TableHead className="text-gray-300">Type</TableHead>
                                    <TableHead className="text-gray-300">Risk Score</TableHead>
                                    <TableHead className="text-gray-300">Crown Jewel</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {nodes.map((node: Node) => (
                                    <TableRow key={node.id} className="border-zinc-700 hover:bg-zinc-700/50">
                                        <TableCell className="font-medium">{node.name}</TableCell>
                                        <TableCell className="capitalize flex items-center gap-2">{nodeTypeIcons[node.nodeType as keyof typeof nodeTypeIcons]} {node.nodeType.replace('_', ' ')}</TableCell>
                                        <TableCell>{node.riskScore ?? 'N/A'}</TableCell>
                                        <TableCell>{node.isCrownJewel ? <Target className="h-5 w-5 text-yellow-400" /> : 'No'}</TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    }
                </TabsContent>
            </Tabs>
        </div>
    );
};

export default AttackPathDiscoveryPage;
