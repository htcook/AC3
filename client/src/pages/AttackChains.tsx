import React, { useState, useMemo } from "react";
import { Link, useLocation } from "wouter";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { toast } from "sonner";
import {
  GitBranch, Plus, Search, ChevronLeft, ChevronRight, MoreHorizontal,
  Trash2, ArrowUpDown, Shield, Zap, Target,
} from "lucide-react";

const SEV_COLORS: Record<string, string> = { critical: "bg-red-500/20 text-red-400 border-red-500/30", high: "bg-orange-500/20 text-orange-400 border-orange-500/30", moderate: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30", low: "bg-blue-500/20 text-blue-400 border-blue-500/30", informational: "bg-gray-500/20 text-gray-400 border-gray-500/30" };
const STATUS_COLORS: Record<string, string> = { active: "bg-red-500/20 text-red-400 border-red-500/30", mitigated: "bg-green-500/20 text-green-400 border-green-500/30", accepted: "bg-purple-500/20 text-purple-400 border-purple-500/30", investigating: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" };

function ScoreBadge({ score }: { score: number | null }) {
  if (score === null || score === undefined) return <span className="text-muted-foreground">\u2014</span>;
  const color = score >= 9 ? "text-red-400" : score >= 7 ? "text-orange-400" : score >= 4 ? "text-yellow-400" : "text-blue-400";
  return <span className={`font-mono font-bold text-lg ${color}`}>{score.toFixed(1)}</span>;
}

export default function AttackChains() {
  const [, navigate] = useLocation();
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [sortBy, setSortBy] = useState<"compositeRiskScore" | "createdAt" | "compositeSeverity" | "name">("compositeRiskScore");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const queryInput = useMemo(() => ({
    page, pageSize, status: statusFilter || undefined, severity: severityFilter || undefined,
    search: search || undefined, sortBy, sortDir,
  }), [page, pageSize, statusFilter, severityFilter, search, sortBy, sortDir]);

  const { data, isLoading, refetch } = trpc.attackChains.list.useQuery(queryInput);
  const summary = trpc.attackChains.summary.useQuery();
  const deleteMut = trpc.attackChains.delete.useMutation({
    onSuccess: () => { refetch(); toast.success("Chain deleted"); },
    onError: (e: any) => toast.error(e.message),
  });

  const handleSort = (col: typeof sortBy) => {
    if (sortBy === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortBy(col); setSortDir("desc"); }
  };

  const s = summary.data;

  return (
    <AppShell activePath="/attack-chains">
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <GitBranch className="h-8 w-8 text-primary" />
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Attack Chains</h1>
              <p className="text-muted-foreground">Linked vulnerability chains with composite risk scoring</p>
            </div>
          </div>
          <Link href="/attack-chains/new"><Button size="sm"><Plus className="h-4 w-4 mr-1" /> New Chain</Button></Link>
        </div>

        {s && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card className="bg-card border-border"><CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-red-400">{s.totalActive}</div>
              <div className="text-xs text-muted-foreground">Active Chains</div>
            </CardContent></Card>
            <Card className="bg-card border-border"><CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-green-400">{s.totalMitigated}</div>
              <div className="text-xs text-muted-foreground">Mitigated</div>
            </CardContent></Card>
            <Card className="bg-card border-border"><CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-orange-400">{s.bySeverity.find((b: any) => b.severity === "critical")?.count || 0}</div>
              <div className="text-xs text-muted-foreground">Critical Chains</div>
            </CardContent></Card>
            <Card className="bg-card border-border"><CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-yellow-400">{s.bySeverity.find((b: any) => b.severity === "high")?.count || 0}</div>
              <div className="text-xs text-muted-foreground">High Chains</div>
            </CardContent></Card>
          </div>
        )}

        {/* Top Chains */}
        {s?.topChains?.length > 0 && (
          <Card className="bg-card border-border">
            <CardHeader><CardTitle className="text-sm flex items-center gap-2"><Zap className="h-4 w-4 text-primary" />Highest Risk Chains</CardTitle></CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
                {s.topChains.map((c: any) => (
                  <div key={c.id} className="p-3 bg-muted/20 rounded-lg cursor-pointer hover:bg-muted/40 transition-colors" onClick={() => navigate(`/attack-chains/${c.id}`)}>
                    <div className="flex items-center justify-between mb-1">
                      <ScoreBadge score={c.compositeRiskScore} />
                      <Badge variant="outline" className={SEV_COLORS[c.compositeSeverity] || ""} >{c.compositeSeverity}</Badge>
                    </div>
                    <p className="text-sm font-medium truncate">{c.name}</p>
                    <p className="text-xs text-muted-foreground truncate">{c.entryPoint || "Unknown entry"} → {c.finalTarget || "?"}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search chain name, ID, entry point..." className="pl-9 bg-card border-border" value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} />
          </div>
          <Select value={statusFilter || "all"} onValueChange={v => { setStatusFilter(v === "all" ? "" : v); setPage(1); }}>
            <SelectTrigger className="w-[150px] bg-card border-border"><SelectValue placeholder="All Statuses" /></SelectTrigger>
            <SelectContent><SelectItem value="all">All Statuses</SelectItem><SelectItem value="active">Active</SelectItem><SelectItem value="mitigated">Mitigated</SelectItem><SelectItem value="accepted">Accepted</SelectItem><SelectItem value="investigating">Investigating</SelectItem></SelectContent>
          </Select>
          <Select value={severityFilter || "all"} onValueChange={v => { setSeverityFilter(v === "all" ? "" : v); setPage(1); }}>
            <SelectTrigger className="w-[140px] bg-card border-border"><SelectValue placeholder="All Severities" /></SelectTrigger>
            <SelectContent><SelectItem value="all">All Severities</SelectItem>{["critical","high","moderate","low","informational"].map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}</SelectContent>
          </Select>
        </div>

        <Card className="bg-card border-border">
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="cursor-pointer" onClick={() => handleSort("compositeRiskScore")}><span className="flex items-center gap-1">Score <ArrowUpDown className="h-3 w-3" /></span></TableHead>
                <TableHead>Chain ID</TableHead>
                <TableHead className="cursor-pointer" onClick={() => handleSort("name")}><span className="flex items-center gap-1">Name <ArrowUpDown className="h-3 w-3" /></span></TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Entry → Target</TableHead>
                <TableHead>Steps</TableHead>
                <TableHead className="cursor-pointer" onClick={() => handleSort("createdAt")}><span className="flex items-center gap-1">Created <ArrowUpDown className="h-3 w-3" /></span></TableHead>
                <TableHead className="w-10"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? Array.from({ length: 5 }).map((_, i) => (
                <TableRow key={i} className="border-border">{Array.from({ length: 9 }).map((_, j) => <TableCell key={j}><div className="h-4 bg-muted rounded animate-pulse" /></TableCell>)}</TableRow>
              )) : !data?.items.length ? (
                <TableRow className="border-border"><TableCell colSpan={9} className="text-center py-12 text-muted-foreground">
                  <GitBranch className="h-12 w-12 mx-auto mb-3 opacity-30" /><p className="font-medium">No attack chains found</p><p className="text-sm mt-1">Create a chain to link related vulnerabilities</p>
                </TableCell></TableRow>
              ) : data.items.map((item: any) => (
                <TableRow key={item.id} className="border-border cursor-pointer hover:bg-muted/30" onClick={() => navigate(`/attack-chains/${item.id}`)}>
                  <TableCell><ScoreBadge score={item.compositeRiskScore} /></TableCell>
                  <TableCell className="font-mono text-xs text-primary">{item.chainId}</TableCell>
                  <TableCell className="max-w-[200px] truncate font-medium">{item.name}</TableCell>
                  <TableCell><Badge variant="outline" className={SEV_COLORS[item.compositeSeverity] || ""}>{item.compositeSeverity}</Badge></TableCell>
                  <TableCell><Badge variant="outline" className={STATUS_COLORS[item.status] || ""}>{item.status}</Badge></TableCell>
                  <TableCell className="text-sm text-muted-foreground max-w-[180px] truncate">{item.entryPoint || "?"} → {item.finalTarget || "?"}</TableCell>
                  <TableCell><Badge variant="outline">{item.stepCount} steps</Badge></TableCell>
                  <TableCell className="text-xs text-muted-foreground">{new Date(item.createdAt).toLocaleDateString()}</TableCell>
                  <TableCell onClick={e => e.stopPropagation()}>
                    <DropdownMenu><DropdownMenuTrigger asChild><Button variant="ghost" size="icon" className="h-7 w-7"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => navigate(`/attack-chains/${item.id}`)}>View Details</DropdownMenuItem>
                        <DropdownMenuItem className="text-red-400" onClick={() => { if (confirm("Delete?")) deleteMut.mutate({ id: item.id, chainId: item.chainId }); }}><Trash2 className="h-4 w-4 mr-2" />Delete</DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>

        {data && data.totalPages > 1 && (
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Showing {(page - 1) * pageSize + 1}\u2013{Math.min(page * pageSize, data.total)} of {data.total}</span>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}><ChevronLeft className="h-4 w-4" /></Button>
              <span className="text-sm">Page {page} of {data.totalPages}</span>
              <Button variant="outline" size="sm" disabled={page >= data.totalPages} onClick={() => setPage(p => p + 1)}><ChevronRight className="h-4 w-4" /></Button>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
