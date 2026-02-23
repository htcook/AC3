
import React, { useState } from 'react';
import { trpc } from '@/lib/trpc';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { TrendingUp, TrendingDown, Minus, AlertCircle, PlusCircle, Trash2, Loader2 } from 'lucide-react';

const RiskTrendingPage: React.FC = () => {
  const [isCreateDialogOpen, setCreateDialogOpen] = useState(false);
  const [newSnapshotScore, setNewSnapshotScore] = useState(850);

  const utils = trpc.useUtils();

  const snapshotsQuery = trpc.riskTrending.listSnapshots.useQuery({ limit: 20 });
  const latestSnapshotQuery = trpc.riskTrending.getLatest.useQuery();
  const trendQuery = trpc.riskTrending.getTrend.useQuery({ days: 30 });

  const createSnapshotMutation = trpc.riskTrending.createSnapshot.useMutation({
    onSuccess: (data) => {
      toast.success(`Snapshot created successfully with ID: ${data.id}`);
      utils.riskTrending.listSnapshots.invalidate();
      utils.riskTrending.getLatest.invalidate();
      utils.riskTrending.getTrend.invalidate();
      setCreateDialogOpen(false);
    },
    onError: (error) => {
      toast.error('Failed to create snapshot', { description: error.message });
    },
  });

  const deleteSnapshotMutation = trpc.riskTrending.deleteSnapshot.useMutation({
    onSuccess: () => {
      toast.success('Snapshot deleted successfully.');
      utils.riskTrending.listSnapshots.invalidate();
      utils.riskTrending.getLatest.invalidate();
      utils.riskTrending.getTrend.invalidate();
    },
    onError: (error) => {
      toast.error('Failed to delete snapshot', { description: error.message });
    },
  });

  const handleCreateSnapshot = () => {
    createSnapshotMutation.mutate({ overallScore: newSnapshotScore });
  };

  const TrendIndicator = () => {
    if (trendQuery.isLoading) return <Loader2 className="h-6 w-6 animate-spin" />;
    if (trendQuery.error) return <AlertCircle className="h-6 w-6 text-red-500" />;
    if (!trendQuery.data) return null;

    const snapshots = trendQuery.data;
    const direction = snapshots.length >= 2 ? (snapshots[0].overallScore > snapshots[snapshots.length - 1].overallScore ? 'improving' : snapshots[0].overallScore === snapshots[snapshots.length - 1].overallScore ? 'stable' : 'declining') : 'stable';
    const changePercent = snapshots.length >= 2 ? Math.abs(snapshots[0].overallScore - snapshots[snapshots.length - 1].overallScore) : 0;
    const periodDays = 30;
    const isImproving = direction === 'improving';
    const isStable = direction === 'stable';
    const color = isImproving ? 'text-green-500' : isStable ? 'text-yellow-500' : 'text-red-500';
    const Icon = isImproving ? TrendingUp : isStable ? Minus : TrendingDown;

    return (
      <div className={`flex items-center gap-2 ${color}`}>
        <Icon className="h-6 w-6" />
        <div className="flex flex-col">
          <span className="font-bold text-lg">{changePercent.toFixed(2)}%</span>
          <span className="text-xs text-muted-foreground">{direction} over last {periodDays} days</span>
        </div>
      </div>
    );
  };

  const LatestScoreCard = () => {
    if (latestSnapshotQuery.isLoading) return <CardSkeleton />;
    if (latestSnapshotQuery.error) return <CardError error={latestSnapshotQuery.error.message} />;
    if (!latestSnapshotQuery.data) return <Card className="text-center p-6">No snapshots found.</Card>;

    const { overallScore, snapshotDate, detectionCoveragePercent, preventionCoveragePercent, criticalVulnCount } = latestSnapshotQuery.data;

    return (
      <Card>
        <CardHeader>
          <CardTitle>Latest Risk Score</CardTitle>
          <CardDescription>As of {new Date(snapshotDate).toLocaleDateString()}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="text-5xl font-bold text-center">{overallScore}</div>
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <p className="text-sm text-muted-foreground">Detection</p>
              <p className="font-semibold">{detectionCoveragePercent ?? 'N/A'}%</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Prevention</p>
              <p className="font-semibold">{preventionCoveragePercent ?? 'N/A'}%</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Critical Vulns</p>
              <p className="font-semibold">{criticalVulnCount ?? 'N/A'}</p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  };

  const SnapshotsTable = () => {
    if (snapshotsQuery.isLoading) return <div className="flex justify-center items-center p-10"><Loader2 className="h-8 w-8 animate-spin" /></div>;
    if (snapshotsQuery.error) return <div className="text-red-500 text-center p-10">Error loading snapshots: {snapshotsQuery.error.message}</div>;
    if (!snapshotsQuery.data || snapshotsQuery.data.length === 0) {
      return (
        <div className="text-center py-10 border-2 border-dashed rounded-lg">
          <h3 className="text-lg font-medium">No Snapshots Yet</h3>
          <p className="text-sm text-muted-foreground">Create your first risk snapshot to start tracking trends.</p>
          <DialogTrigger asChild>
             <Button className="mt-4">Create Snapshot</Button>
          </DialogTrigger>
        </div>
      );
    }

    return (
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Date</TableHead>
              <TableHead className="text-right">Overall Score</TableHead>
              <TableHead className="text-right">Detection</TableHead>
              <TableHead className="text-right">Prevention</TableHead>
              <TableHead className="text-right">Critical Vulns</TableHead>
              <TableHead>Source</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {snapshotsQuery.data.map((s) => (
              <TableRow key={s.id}>
                <TableCell>{new Date(s.snapshotDate).toLocaleDateString()}</TableCell>
                <TableCell className="text-right font-medium">{s.overallScore}</TableCell>
                <TableCell className="text-right">{s.detectionCoveragePercent ?? 'N/A'}%</TableCell>
                <TableCell className="text-right">{s.preventionCoveragePercent ?? 'N/A'}%</TableCell>
                <TableCell className="text-right">{s.criticalVulnCount ?? 'N/A'}</TableCell>
                <TableCell><Badge variant="outline">{s.source ?? 'Manual'}</Badge></TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => deleteSnapshotMutation.mutate({ id: s.id })}
                    disabled={deleteSnapshotMutation.isPending}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>
    );
  };

  const CardSkeleton = () => (
    <Card>
      <CardHeader><div className="h-6 w-3/4 bg-muted rounded-md animate-pulse"></div></CardHeader>
      <CardContent className="grid gap-4">
        <div className="h-12 w-1/2 mx-auto bg-muted rounded-md animate-pulse"></div>
        <div className="grid grid-cols-3 gap-4">
          <div className="h-8 bg-muted rounded-md animate-pulse"></div>
          <div className="h-8 bg-muted rounded-md animate-pulse"></div>
          <div className="h-8 bg-muted rounded-md animate-pulse"></div>
        </div>
      </CardContent>
    </Card>
  );

  const CardError = ({ error }: { error: string }) => (
    <Card className="border-red-500/50">
      <CardHeader><CardTitle className="text-red-500">Error</CardTitle></CardHeader>
      <CardContent className="flex items-center gap-4">
        <AlertCircle className="h-8 w-8 text-red-500" />
        <p className="text-sm text-red-400">{error}</p>
      </CardContent>
    </Card>
  );

  return (
    <div className="bg-background text-foreground p-6 space-y-6">
      <Dialog open={isCreateDialogOpen} onOpenChange={setCreateDialogOpen}>
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold">Risk Trending</h1>
            <p className="text-muted-foreground">Executive dashboard for tracking risk posture over time.</p>
          </div>
          <DialogTrigger asChild>
            <Button>
              <PlusCircle className="mr-2 h-4 w-4" />
              Create Snapshot
            </Button>
          </DialogTrigger>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <LatestScoreCard />
          <Card>
            <CardHeader><CardTitle>Risk Trend</CardTitle></CardHeader>
            <CardContent className="flex items-center justify-center h-full">
              <TrendIndicator />
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>ATT&CK Tactic Scores</CardTitle></CardHeader>
            <CardContent className="text-center text-muted-foreground">
              <p>Tactic-level drilldown coming soon.</p>
            </CardContent>
          </Card>
        </div>

        <div>
          <h2 className="text-2xl font-semibold mb-4">Historical Snapshots</h2>
          <SnapshotsTable />
        </div>

        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Risk Snapshot</DialogTitle>
            <DialogDescription>
              Manually create a snapshot of the current risk score. This is useful for capturing point-in-time measurements.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <label htmlFor="score" className="text-sm font-medium">Overall Score</label>
            <Input
              id="score"
              type="number"
              value={newSnapshotScore}
              onChange={(e) => setNewSnapshotScore(Number(e.target.value))}
              className="col-span-3"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleCreateSnapshot} disabled={createSnapshotMutation.isPending}>
              {createSnapshotMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default RiskTrendingPage;
