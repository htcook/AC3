import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Loader2, RefreshCw, Plus } from "lucide-react";

const RemediationVerificationPage = () => {
  const [isCreateOpen, setCreateOpen] = useState(false);
  const tasksQuery = trpc.remediationVerification.list.useQuery({} as any);
  const utils = trpc.useUtils();
  const executeMutation = trpc.remediationVerification.execute.useMutation({
    onSuccess: () => { utils.remediationVerification.list.invalidate(); toast.success("Verification executed."); },
    onError: (err: any) => toast.error("Failed: " + err.message),
  });
  const statusBadge = (status: string) => {
    const map: Record<string, string> = { pending: "outline", running: "secondary", remediated: "default", still_vulnerable: "destructive", error: "destructive" };
    return <Badge variant={(map[status] || "outline") as any}>{status.replace("_", " ")}</Badge>;
  };
  return (
    <div className="p-8 bg-background text-foreground min-h-screen">
      <header className="flex justify-between items-center mb-8">
        <div><h1 className="text-3xl font-bold">Remediation Verification</h1><p className="text-muted-foreground mt-1">Re-validate findings after remediation</p></div>
        <Dialog open={isCreateOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild><Button><Plus className="mr-2 h-4 w-4" /> New Verification</Button></DialogTrigger>
          <DialogContent><DialogHeader><DialogTitle>Create Verification Task</DialogTitle></DialogHeader><CreateTaskForm onClose={() => setCreateOpen(false)} /></DialogContent>
        </Dialog>
      </header>
      <Card><CardHeader><CardTitle>Verification Tasks</CardTitle></CardHeader><CardContent>
        {tasksQuery.isLoading && <div className="flex justify-center p-8"><Loader2 className="h-8 w-8 animate-spin" /></div>}
        {tasksQuery.isError && <p className="text-red-500">Error: {tasksQuery.error.message}</p>}
        {tasksQuery.data && tasksQuery.data.length === 0 && <p className="text-muted-foreground text-center py-8">No tasks yet.</p>}
        {tasksQuery.data && tasksQuery.data.length > 0 && (
          <Table><TableHeader><TableRow><TableHead>Finding</TableHead><TableHead>Type</TableHead><TableHead>Status</TableHead><TableHead>Severity</TableHead><TableHead>Verified At</TableHead><TableHead className="text-right">Actions</TableHead></TableRow></TableHeader>
            <TableBody>{tasksQuery.data.map((task: any) => (
              <TableRow key={task.id}><TableCell className="font-medium">{task.findingTitle}</TableCell><TableCell className="capitalize">{task.verificationType.replace("_", " ")}</TableCell><TableCell>{statusBadge(task.status)}</TableCell><TableCell className="capitalize">{task.originalSeverity}</TableCell><TableCell>{task.verifiedAt ? new Date(task.verifiedAt).toLocaleString() : "\u2014"}</TableCell>
                <TableCell className="text-right"><Button size="sm" variant="outline" onClick={() => executeMutation.mutate({ id: task.id })} disabled={executeMutation.isPending}>{executeMutation.isPending ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : <RefreshCw className="mr-1 h-3 w-3" />} Re-verify</Button></TableCell></TableRow>
            ))}</TableBody></Table>
        )}
      </CardContent></Card>
    </div>
  );
};
const CreateTaskForm = ({ onClose }: { onClose: () => void }) => {
  const [findingTitle, setFindingTitle] = useState("");
  const [verificationType, setVerificationType] = useState<"rescan" | "exploit_retest" | "config_check" | "manual">("rescan");
  const [originalSeverity, setOriginalSeverity] = useState<"critical" | "high" | "medium" | "low" | "info">("high");
  const utils = trpc.useUtils();
  const createMutation = trpc.remediationVerification.create.useMutation({
    onSuccess: () => { utils.remediationVerification.list.invalidate(); toast.success("Task created."); onClose(); },
    onError: (err: any) => toast.error("Failed: " + err.message),
  });
  return (
    <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate({ findingTitle, verificationType, originalSeverity } as any); }} className="space-y-4">
      <Input placeholder="Finding title" value={findingTitle} onChange={(e) => setFindingTitle(e.target.value)} required />
      <Select value={verificationType} onValueChange={(v: any) => setVerificationType(v)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="rescan">Rescan</SelectItem><SelectItem value="exploit_retest">Exploit Retest</SelectItem><SelectItem value="config_check">Config Check</SelectItem><SelectItem value="manual">Manual</SelectItem></SelectContent></Select>
      <Select value={originalSeverity} onValueChange={(v: any) => setOriginalSeverity(v)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="critical">Critical</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="low">Low</SelectItem><SelectItem value="info">Info</SelectItem></SelectContent></Select>
      <Button type="submit" disabled={createMutation.isPending}>{createMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Create Task</Button>
    </form>
  );
};
export default RemediationVerificationPage;
