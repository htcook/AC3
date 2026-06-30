import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  CircuitBoard, ChevronLeft, Search, Shield, Terminal, Network,
  Eye, Key, Cpu, Globe, Lock, Zap, Brain, Boxes, RefreshCw,
  Flame, Server, Activity, AlertTriangle
} from "lucide-react";
import { Link } from "wouter";

const CATEGORY_COLORS: Record<string, string> = {
  reconnaissance: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  credential_access: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  execution: "bg-red-500/20 text-red-400 border-red-500/30",
  persistence: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  privilege_escalation: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  lateral_movement: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  defense_evasion: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  exfiltration: "bg-violet-500/20 text-violet-400 border-violet-500/30",
  collection: "bg-teal-500/20 text-teal-400 border-teal-500/30",
  impact: "bg-rose-500/20 text-rose-400 border-rose-500/30",
};

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  reconnaissance: <Search className="w-4 h-4" />,
  credential_access: <Key className="w-4 h-4" />,
  execution: <Terminal className="w-4 h-4" />,
  persistence: <Lock className="w-4 h-4" />,
  privilege_escalation: <Zap className="w-4 h-4" />,
  lateral_movement: <Network className="w-4 h-4" />,
  defense_evasion: <Shield className="w-4 h-4" />,
  exfiltration: <Globe className="w-4 h-4" />,
  collection: <Eye className="w-4 h-4" />,
  impact: <AlertTriangle className="w-4 h-4" />,
};

export default function EmberCapabilities() {
  const [searchFilter, setSearchFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");

  const metadataQuery = trpc.ember.getMetadata.useQuery(undefined, { refetchInterval: 60000 });
  const capabilities = metadataQuery.data?.capabilities || [];

  const categories = useMemo(() => {
    const cats = new Set(capabilities.map((c: any) => c.category));
    return Array.from(cats).sort();
  }, [capabilities]);

  const filteredCapabilities = useMemo(() => {
    return capabilities.filter((cap: any) => {
      const matchesSearch = !searchFilter ||
        cap.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
        cap.id.toLowerCase().includes(searchFilter.toLowerCase()) ||
        cap.description?.toLowerCase().includes(searchFilter.toLowerCase());
      const matchesCategory = categoryFilter === "all" || cap.category === categoryFilter;
      return matchesSearch && matchesCategory;
    });
  }, [capabilities, searchFilter, categoryFilter]);

  const groupedCapabilities = useMemo(() => {
    const groups: Record<string, any[]> = {};
    filteredCapabilities.forEach((cap: any) => {
      if (!groups[cap.category]) groups[cap.category] = [];
      groups[cap.category].push(cap);
    });
    return groups;
  }, [filteredCapabilities]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link href="/ember">
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <ChevronLeft className="w-4 h-4" />
            </Button>
          </Link>
          <div className="p-2 rounded-lg bg-gradient-to-br from-amber-500/20 to-orange-600/20 border border-amber-500/30">
            <CircuitBoard className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Capability Catalog</h1>
            <p className="text-sm text-muted-foreground">
              {capabilities.length} modules across {categories.length} MITRE ATT&CK categories
            </p>
          </div>
        </div>
        <Button variant="outline" size="icon" onClick={() => metadataQuery.refetch()}>
          <RefreshCw className="w-4 h-4" />
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {categories.slice(0, 5).map((cat: string) => (
          <Card key={cat} className="bg-card/50 border-border/50">
            <CardContent className="p-3 flex items-center gap-3">
              <div className={`p-2 rounded-lg ${CATEGORY_COLORS[cat] || "bg-zinc-500/20"}`}>
                {CATEGORY_ICONS[cat] || <CircuitBoard className="w-4 h-4" />}
              </div>
              <div>
                <p className="text-lg font-bold text-foreground">
                  {capabilities.filter((c: any) => c.category === cat).length}
                </p>
                <p className="text-[10px] text-muted-foreground capitalize">{cat.replace(/_/g, " ")}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search capabilities..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Button
            variant={categoryFilter === "all" ? "default" : "outline"}
            size="sm"
            className="h-7 text-xs"
            onClick={() => setCategoryFilter("all")}
          >
            All
          </Button>
          {categories.map((cat: string) => (
            <Button
              key={cat}
              variant={categoryFilter === cat ? "default" : "outline"}
              size="sm"
              className="h-7 text-xs capitalize"
              onClick={() => setCategoryFilter(cat)}
            >
              {cat.replace(/_/g, " ")}
            </Button>
          ))}
        </div>
      </div>

      {/* Capability Grid */}
      {metadataQuery.isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {[...Array(9)].map((_, i) => (
            <Card key={i} className="bg-card/30 border-border/30 animate-pulse">
              <CardContent className="p-5 h-32" />
            </Card>
          ))}
        </div>
      ) : Object.keys(groupedCapabilities).length === 0 ? (
        <Card className="bg-card/30 border-border/30">
          <CardContent className="p-8 text-center">
            <CircuitBoard className="w-12 h-12 text-muted-foreground/20 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No capabilities match your filter.</p>
          </CardContent>
        </Card>
      ) : (
        Object.entries(groupedCapabilities).map(([category, caps]) => (
          <div key={category} className="space-y-3">
            <div className="flex items-center gap-2">
              <div className={`p-1.5 rounded-md ${CATEGORY_COLORS[category] || "bg-zinc-500/20"}`}>
                {CATEGORY_ICONS[category] || <CircuitBoard className="w-3.5 h-3.5" />}
              </div>
              <h2 className="text-sm font-semibold text-foreground capitalize">{category.replace(/_/g, " ")}</h2>
              <Badge variant="outline" className="text-[10px]">{caps.length}</Badge>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
              {caps.map((cap: any) => (
                <Card key={cap.id} className="bg-card/40 border-border/30 hover:border-amber-500/30 transition-colors">
                  <CardContent className="p-3.5">
                    <div className="flex items-start justify-between mb-1.5">
                      <span className="text-sm font-medium text-foreground">{cap.name}</span>
                      <Badge variant="outline" className="text-[9px] font-mono">{cap.id}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed mb-2">{cap.description}</p>
                    <div className="flex items-center gap-2">
                      <div className="flex gap-1">
                        {cap.platforms?.map((p: string) => (
                          <Badge key={p} variant="outline" className="text-[9px] h-4">
                            {p === "windows" ? "Win" : p === "linux" ? "Lin" : "Mac"}
                          </Badge>
                        ))}
                      </div>
                      {cap.mitreId && (
                        <Badge variant="outline" className="text-[9px] h-4 bg-red-500/10 text-red-400 border-red-500/30">
                          {cap.mitreId}
                        </Badge>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}
