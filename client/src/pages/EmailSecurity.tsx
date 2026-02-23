import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Mail, Plus, Play, CheckCircle, XCircle, AlertTriangle, Loader2 } from "lucide-react";

export default function EmailSecurity() {

  const [showForm, setShowForm] = useState(false);
  const [gateway, setGateway] = useState<string>("");
  const [targetEmail, setTargetEmail] = useState("");
  const [testType, setTestType] = useState<string>("");
  const [payload, setPayload] = useState("");

  const tests = trpc.emailSecurity.listTests.useQuery();
  const createMut = trpc.emailSecurity.createTest.useMutation({
    onSuccess: () => { toast.success("Test created"); tests.refetch(); setShowForm(false); },
    onError: (e: any) => toast.error(e.message),
  });
  const executeMut = trpc.emailSecurity.executeTest.useMutation({
    onSuccess: (d: any) => { toast.success("Test " + d.result); tests.refetch(); },
    onError: (e: any) => toast.error(e.message),
  });

  const stats = useMemo(() => {
    const all = tests.data ?? [];
    const blocked = all.filter((t: any) => t.result === "blocked").length;
    const delivered = all.filter((t: any) => t.result === "delivered").length;
    const quarantined = all.filter((t: any) => t.result === "quarantined").length;
    return { blocked, delivered, quarantined, total: all.length };
  }, [tests.data]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Mail className="h-6 w-6 text-purple-400" />
            Email Security Gateway Validation
          </h1>
          <p className="text-muted-foreground mt-1">Test Proofpoint, Mimecast, and Defender email controls</p>
        </div>
        <Button onClick={() => setShowForm(!showForm)}><Plus className="h-4 w-4 mr-2" /> New Test</Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card><CardContent className="pt-6"><div className="text-sm text-muted-foreground">Total</div><div className="text-3xl font-bold">{stats.total}</div></CardContent></Card>
        <Card><CardContent className="pt-6"><div className="text-sm text-muted-foreground">Blocked</div><div className="text-3xl font-bold text-green-400">{stats.blocked}</div></CardContent></Card>
        <Card><CardContent className="pt-6"><div className="text-sm text-muted-foreground">Delivered</div><div className="text-3xl font-bold text-red-400">{stats.delivered}</div></CardContent></Card>
        <Card><CardContent className="pt-6"><div className="text-sm text-muted-foreground">Quarantined</div><div className="text-3xl font-bold text-yellow-400">{stats.quarantined}</div></CardContent></Card>
      </div>

      {showForm && (
        <Card>
          <CardHeader><CardTitle>Create Email Security Test</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div><Label>Gateway</Label>
                <Select value={gateway} onValueChange={setGateway}>
                  <SelectTrigger><SelectValue placeholder="Select gateway" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="proofpoint">Proofpoint</SelectItem>
                    <SelectItem value="mimecast">Mimecast</SelectItem>
                    <SelectItem value="defender">Microsoft Defender</SelectItem>
                    <SelectItem value="barracuda">Barracuda</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div><Label>Test Type</Label>
                <Select value={testType} onValueChange={setTestType}>
                  <SelectTrigger><SelectValue placeholder="Select test" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="phishing">Phishing Link</SelectItem>
                    <SelectItem value="malware">Malware Attachment</SelectItem>
                    <SelectItem value="spoofing">Spoofing</SelectItem>
                    <SelectItem value="dlp">DLP Trigger</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div><Label>Target Email</Label><Input value={targetEmail} onChange={(e) => setTargetEmail(e.target.value)} placeholder="test@corp.com" /></div>
              <div><Label>Payload</Label><Input value={payload} onChange={(e) => setPayload(e.target.value)} placeholder="EICAR test" /></div>
            </div>
            <Button disabled={!gateway || !testType || !targetEmail || createMut.isPending}
              onClick={() => createMut.mutate({ gateway: gateway as any, testType: testType as any, targetEmail, payload })}>
              {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null} Create Test
            </Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader><CardTitle>Test History</CardTitle><CardDescription>{tests.data?.length ?? 0} tests</CardDescription></CardHeader>
        <CardContent>
          {tests.isLoading ? <div className="flex justify-center py-8"><Loader2 className="h-6 w-6 animate-spin" /></div>
          : !tests.data?.length ? <p className="text-muted-foreground text-center py-8">No tests yet</p>
          : <div className="space-y-2">{tests.data.map((t: any) => (
              <div key={t.id} className="flex items-center justify-between p-3 rounded-lg border">
                <div className="flex items-center gap-3">
                  {t.result === "blocked" && <CheckCircle className="h-4 w-4 text-green-400" />}
                  {t.result === "delivered" && <XCircle className="h-4 w-4 text-red-400" />}
                  {t.result === "quarantined" && <AlertTriangle className="h-4 w-4 text-yellow-400" />}
                  <Badge variant="outline">{t.gateway}</Badge>
                  <Badge>{t.testType}</Badge>
                  <span className="text-sm">{t.targetEmail}</span>
                </div>
                <div className="flex items-center gap-2">
                  {t.result ? <Badge variant={t.result === "blocked" ? "default" : "destructive"}>{t.result}</Badge>
                  : <Button size="sm" onClick={() => executeMut.mutate({ testId: t.id })} disabled={executeMut.isPending}>
                      <Play className="h-3 w-3 mr-1" /> Execute
                    </Button>}
                </div>
              </div>
            ))}</div>}
        </CardContent>
      </Card>
    </div>
  );
}
