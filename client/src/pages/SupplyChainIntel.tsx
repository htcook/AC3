import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { useState, useMemo, useRef, useEffect, useCallback } from "react";
import {
  Shield, AlertTriangle, Building2, Package, Link2, Search,
  Plus, RefreshCw, Loader2, ChevronRight, ExternalLink,
  TrendingUp, Activity, Layers, Network, BarChart3, Filter,
  CheckCircle2, XCircle, Clock, Eye,
} from "lucide-react";
import { toast } from "sonner";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";

// ─── Data Source Badge ───────────────────────────────────────────────────
const DATA_SOURCE_STYLES: Record<string, { label: string; bg: string; text: string; border: string; icon: string }> = {
  osint: { label: "OSINT", bg: "bg-emerald-500/15", text: "text-emerald-400", border: "border-emerald-500/40", icon: "🌐" },
  demo: { label: "DEMO", bg: "bg-amber-500/15", text: "text-amber-400", border: "border-amber-500/40", icon: "⚠️" },
  customer: { label: "CUSTOMER", bg: "bg-blue-500/15", text: "text-blue-400", border: "border-blue-500/40", icon: "🔒" },
};

function DataSourceBadge({ source, url }: { source?: string; url?: string | null }) {
  const style = DATA_SOURCE_STYLES[source || "demo"] || DATA_SOURCE_STYLES.demo;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${style.bg} ${style.text} ${style.border}`}
      title={url ? `Source: ${url}` : `Data source: ${style.label}`}>
      <span className="text-[9px]">{style.icon}</span>
      {style.label}
    </span>
  );
}

// ─── Severity Colors ─────────────────────────────────────────────────────
const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

const TIER_COLORS: Record<string, string> = {
  prime: "text-purple-400 bg-purple-500/10",
  tier1: "text-blue-400 bg-blue-500/10",
  tier2: "text-cyan-400 bg-cyan-500/10",
  tier3: "text-slate-400 bg-slate-500/10",
};

const STATUS_COLORS: Record<string, string> = {
  active: "text-emerald-400 bg-emerald-500/10",
  inactive: "text-slate-400 bg-slate-500/10",
  under_review: "text-amber-400 bg-amber-500/10",
  suspended: "text-red-400 bg-red-500/10",
};

const MITIGATION_COLORS: Record<string, string> = {
  unmitigated: "text-red-400",
  investigating: "text-amber-400",
  mitigating: "text-blue-400",
  mitigated: "text-emerald-400",
  accepted_risk: "text-slate-400",
};

// ─── Main Component ──────────────────────────────────────────────────────
export default function SupplyChainIntel() {
  const [activeTab, setActiveTab] = useState<"dashboard" | "suppliers" | "alerts" | "relationships">("dashboard");
  const [searchTerm, setSearchTerm] = useState("");
  const [tierFilter, setTierFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [showAddSupplier, setShowAddSupplier] = useState(false);

  // ─── Queries ─────────────────────────────────────────────────────────
  const dashboard = trpc.supplyChain.getDashboard.useQuery(undefined, {
    refetchInterval: 60000,
  });

  const suppliers = trpc.supplyChain.listSuppliers.useQuery(
    { search: searchTerm || undefined, tier: tierFilter !== "all" ? tierFilter : undefined, limit: 50, offset: 0 },
    { enabled: activeTab === "suppliers" }
  );

  const alerts = trpc.supplyChain.listAlerts.useQuery(
    { severity: severityFilter !== "all" ? severityFilter : undefined, limit: 50, offset: 0 },
    { enabled: activeTab === "alerts" }
  );

  // ─── Mutations ───────────────────────────────────────────────────────
  const runCorrelation = trpc.supplyChain.runCorrelation.useMutation({
    onSuccess: (data) => {
      toast.success(`Correlation complete: ${data.alertsGenerated} alerts from ${data.processed} reports`);
      dashboard.refetch();
      alerts.refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err.message)),
  });

  const updateAlertStatus = trpc.supplyChain.updateAlertStatus.useMutation({
    onSuccess: () => {
      toast.success("Alert status updated");
      alerts.refetch();
      dashboard.refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err.message)),
  });

  // ─── Dashboard Tab ───────────────────────────────────────────────────
  function DashboardView() {
    const d = dashboard.data;
    if (dashboard.isLoading) return <LoadingState />;
    if (!d) return <EmptyState message="No supply chain data available" />;

    return (
      <div className="space-y-6">
        {/* KPI Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <KPICard icon={Building2} label="Total Suppliers" value={d.totalSuppliers} color="text-blue-400" />
          <KPICard icon={AlertTriangle} label="Active Alerts" value={d.activeAlerts} color="text-red-400" />
          <KPICard icon={Shield} label="Critical Alerts" value={d.criticalAlerts} color="text-orange-400" />
          <KPICard icon={Network} label="Relationships" value={d.totalRelationships} color="text-purple-400" />
        </div>

        {/* Tier Breakdown */}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            Supplier Tier Distribution
          </h3>
          <div className="grid grid-cols-4 gap-3">
            {Object.entries(d.byTier || {}).map(([tier, count]) => (
              <div key={tier} className="bg-slate-900/50 rounded-lg p-3 text-center">
                <div className={`text-xs uppercase font-medium ${TIER_COLORS[tier] || "text-slate-400"} mb-1`}>{tier}</div>
                <div className="text-xl font-bold text-white">{count as number}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-red-400" />
              Recent Threat Alerts
            </h3>
            <button
              onClick={() => runCorrelation.mutate({ lookbackHours: 24 })}
              disabled={runCorrelation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-blue-600/20 text-blue-400 border border-blue-500/30 rounded-md hover:bg-blue-600/30 transition-colors disabled:opacity-50"
            >
              {runCorrelation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
              Run Correlation
            </button>
          </div>
          {d.recentAlerts && d.recentAlerts.length > 0 ? (
            <div className="space-y-2">
              {d.recentAlerts.slice(0, 8).map((alert: any) => (
                <div key={alert.id} className={`flex items-center gap-3 p-3 rounded-lg border ${SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.medium}`}>
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-white truncate">{alert.title}</div>
                    <div className="text-xs text-slate-400">{alert.supplierName} • {alert.matchedProduct}</div>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${MITIGATION_COLORS[alert.mitigationStatus] || ""}`}>
                    {alert.mitigationStatus}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-500 text-center py-4">No recent alerts. Supply chain is clear.</p>
          )}
        </div>
      </div>
    );
  }

  // ─── Suppliers Tab ───────────────────────────────────────────────────
  function SuppliersView() {
    if (suppliers.isLoading) return <LoadingState />;
    const data = suppliers.data;

    return (
      <div className="space-y-4">
        {/* Filters */}
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search suppliers..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-slate-800/50 border border-slate-700/50 rounded-lg text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500/50"
            />
          </div>
          <select
            value={tierFilter}
            onChange={(e) => setTierFilter(e.target.value)}
            className="px-3 py-2 bg-slate-800/50 border border-slate-700/50 rounded-lg text-sm text-white focus:outline-none focus:border-blue-500/50"
          >
            <option value="all">All Tiers</option>
            <option value="prime">Prime</option>
            <option value="tier1">Tier 1</option>
            <option value="tier2">Tier 2</option>
            <option value="tier3">Tier 3</option>
          </select>
          <button
            onClick={() => setShowAddSupplier(true)}
            className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add Supplier
          </button>
        </div>

        {/* Supplier List */}
        {data?.suppliers && data.suppliers.length > 0 ? (
          <div className="space-y-2">
            {data.suppliers.map((supplier: any) => (
              <div key={supplier.supplierId} className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 hover:border-slate-600/50 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Building2 className="w-5 h-5 text-blue-400" />
                    <div>
                      <div className="text-sm font-semibold text-white flex items-center gap-2">
                        {supplier.name}
                        <DataSourceBadge source={supplier.dataSource} url={supplier.dataSourceUrl} />
                      </div>
                      <div className="text-xs text-slate-400">
                        {supplier.cageCode && <span className="mr-2">CAGE: {supplier.cageCode}</span>}
                        {supplier.dunsNumber && <span>DUNS: {supplier.dunsNumber}</span>}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${TIER_COLORS[supplier.tier] || ""}`}>
                      {supplier.tier}
                    </span>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${STATUS_COLORS[supplier.status] || ""}`}>
                      {supplier.status}
                    </span>
                    {supplier.riskScore > 0 && (
                      <span className={`text-xs px-2 py-0.5 rounded-full ${
                        supplier.riskScore >= 70 ? "text-red-400 bg-red-500/10" :
                        supplier.riskScore >= 40 ? "text-amber-400 bg-amber-500/10" :
                        "text-emerald-400 bg-emerald-500/10"
                      }`}>
                        Risk: {supplier.riskScore}
                      </span>
                    )}
                  </div>
                </div>
                {supplier.primaryProducts && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {(supplier.primaryProducts as string[]).slice(0, 5).map((product: string, i: number) => (
                      <span key={i} className="text-xs px-2 py-0.5 bg-slate-700/50 text-slate-300 rounded">
                        {product}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <EmptyState message="No suppliers found. Add your first defense supplier to start tracking supply chain threats." />
        )}
      </div>
    );
  }

  // ─── Alerts Tab ──────────────────────────────────────────────────────
  function AlertsView() {
    if (alerts.isLoading) return <LoadingState />;
    const data = alerts.data;

    return (
      <div className="space-y-4">
        {/* Filters */}
        <div className="flex items-center gap-3">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 bg-slate-800/50 border border-slate-700/50 rounded-lg text-sm text-white focus:outline-none focus:border-blue-500/50"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button
            onClick={() => runCorrelation.mutate({ lookbackHours: 72 })}
            disabled={runCorrelation.isPending}
            className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium bg-slate-700/50 text-slate-300 border border-slate-600/50 rounded-lg hover:bg-slate-700 transition-colors disabled:opacity-50"
          >
            {runCorrelation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
            Re-correlate (72h)
          </button>
        </div>

        {/* Alert List */}
        {data?.alerts && data.alerts.length > 0 ? (
          <div className="space-y-2">
            {data.alerts.map((alert: any) => (
              <div key={alert.id} className={`bg-slate-800/50 border rounded-lg p-4 ${SEVERITY_COLORS[alert.severity] || "border-slate-700/50"}`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                      <span className="text-sm font-semibold text-white truncate">{alert.title}</span>
                      <DataSourceBadge source={alert.dataSource} />
                    </div>
                    <div className="text-xs text-slate-400 space-y-0.5">
                      <div>Supplier: <span className="text-slate-300">{alert.supplierName}</span></div>
                      <div>Product: <span className="text-slate-300">{alert.matchedProduct} ({alert.matchedVendor})</span></div>
                      {alert.cveIds && <div>CVEs: <span className="text-red-300">{alert.cveIds}</span></div>}
                      {alert.threatActorName && <div>Actor: <span className="text-orange-300">{alert.threatActorName}</span></div>}
                      <div>Cascade Risk: <span className={`font-medium ${
                        alert.cascadeRisk === 'critical' ? 'text-red-400' :
                        alert.cascadeRisk === 'high' ? 'text-orange-400' : 'text-slate-300'
                      }`}>{alert.cascadeRisk}</span></div>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${SEVERITY_COLORS[alert.severity] || ""}`}>
                      {alert.severity}
                    </span>
                    <select
                      value={alert.mitigationStatus}
                      onChange={(e) => updateAlertStatus.mutate({ alertId: alert.id, status: e.target.value })}
                      className="text-xs px-2 py-1 bg-slate-900/50 border border-slate-700/50 rounded text-slate-300 focus:outline-none"
                    >
                      <option value="unmitigated">Unmitigated</option>
                      <option value="investigating">Investigating</option>
                      <option value="mitigating">Mitigating</option>
                      <option value="mitigated">Mitigated</option>
                      <option value="accepted_risk">Accepted Risk</option>
                    </select>
                    <span className="text-xs text-slate-500">
                      {new Date(alert.detectedAt).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState message="No threat alerts. Your supply chain is currently clear of known threats." />
        )}
      </div>
    );
  }

  // ─── Helper Components ───────────────────────────────────────────────
  function KPICard({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
    return (
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-2">
          <Icon className={`w-4 h-4 ${color}`} />
          <span className="text-xs text-slate-400 uppercase tracking-wider">{label}</span>
        </div>
        <div className="text-2xl font-bold text-white">{value}</div>
      </div>
    );
  }

  function LoadingState() {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
        <span className="ml-2 text-sm text-slate-400">Loading supply chain data...</span>
      </div>
    );
  }

  function EmptyState({ message }: { message: string }) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Shield className="w-12 h-12 text-slate-600 mb-3" />
        <p className="text-sm text-slate-400">{message}</p>
      </div>
    );
  }

  // ─── Relationship Graph Tab ──────────────────────────────────────────
  function RelationshipGraphView() {
    const supplyChainMap = trpc.supplyChain.getSupplyChainMap.useQuery(undefined, {
      enabled: activeTab === "relationships",
    });
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const animFrameRef = useRef<number>(0);
    const [hoveredNode, setHoveredNode] = useState<string | null>(null);
    const [selectedNode, setSelectedNode] = useState<string | null>(null);

    // Build graph data from supply chain map
    const graphData = useMemo(() => {
      if (!supplyChainMap.data) return { nodes: [], links: [] };
      const { suppliers, relationships } = supplyChainMap.data as any;
      if (!suppliers || !relationships) return { nodes: [], links: [] };

      const nodes = suppliers.map((s: any) => ({
        id: s.supplierId,
        name: s.name,
        tier: s.tier,
        sector: s.sector,
        alertCount: s.alertCount || 0,
        x: 0, y: 0, vx: 0, vy: 0,
      }));

      const links = relationships.map((r: any) => ({
        source: r.primeContractorId,
        target: r.subcontractorId,
        program: r.programName,
        singleSource: r.singleSourceRisk,
        criticality: r.criticalityToProgram,
      }));

      return { nodes, links };
    }, [supplyChainMap.data]);

    // Simple force simulation on canvas
    useEffect(() => {
      const canvas = canvasRef.current;
      if (!canvas || graphData.nodes.length === 0) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const width = canvas.width = canvas.offsetWidth * 2;
      const height = canvas.height = canvas.offsetHeight * 2;
      ctx.scale(2, 2);
      const w = width / 2;
      const h = height / 2;

      // Initialize positions by tier
      const tierY: Record<string, number> = { prime: h * 0.2, tier1: h * 0.4, tier2: h * 0.65, tier3: h * 0.85 };
      graphData.nodes.forEach((node, i) => {
        const tierNodes = graphData.nodes.filter(n => n.tier === node.tier);
        const idx = tierNodes.indexOf(node);
        const spacing = w / (tierNodes.length + 1);
        node.x = spacing * (idx + 1);
        node.y = (tierY[node.tier] || h * 0.5) + (Math.random() - 0.5) * 30;
      });

      // Simple force simulation
      const simulate = () => {
        // Repulsion between nodes
        for (let i = 0; i < graphData.nodes.length; i++) {
          for (let j = i + 1; j < graphData.nodes.length; j++) {
            const a = graphData.nodes[i];
            const b = graphData.nodes[j];
            const dx = b.x - a.x;
            const dy = b.y - a.y;
            const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
            const force = 800 / (dist * dist);
            a.vx -= dx / dist * force;
            a.vy -= dy / dist * force;
            b.vx += dx / dist * force;
            b.vy += dy / dist * force;
          }
        }

        // Attraction along links
        for (const link of graphData.links) {
          const source = graphData.nodes.find(n => n.id === link.source);
          const target = graphData.nodes.find(n => n.id === link.target);
          if (!source || !target) continue;
          const dx = target.x - source.x;
          const dy = target.y - source.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          const force = (dist - 120) * 0.01;
          source.vx += dx / dist * force;
          source.vy += dy / dist * force;
          target.vx -= dx / dist * force;
          target.vy -= dy / dist * force;
        }

        // Tier gravity (keep nodes in their tier band)
        for (const node of graphData.nodes) {
          const targetY = tierY[node.tier] || h * 0.5;
          node.vy += (targetY - node.y) * 0.05;
        }

        // Apply velocity with damping
        for (const node of graphData.nodes) {
          node.vx *= 0.7;
          node.vy *= 0.7;
          node.x += node.vx;
          node.y += node.vy;
          // Bounds
          node.x = Math.max(60, Math.min(w - 60, node.x));
          node.y = Math.max(30, Math.min(h - 30, node.y));
        }
      };

      const tierColors: Record<string, string> = {
        prime: '#a78bfa', tier1: '#60a5fa', tier2: '#22d3ee', tier3: '#94a3b8',
      };

      const draw = () => {
        simulate();
        ctx.clearRect(0, 0, w, h);

        // Draw tier labels
        ctx.font = '10px Inter, sans-serif';
        ctx.fillStyle = '#475569';
        Object.entries(tierY).forEach(([tier, y]) => {
          ctx.fillText(tier.toUpperCase(), 10, y - 15);
        });

        // Draw links
        for (const link of graphData.links) {
          const source = graphData.nodes.find(n => n.id === link.source);
          const target = graphData.nodes.find(n => n.id === link.target);
          if (!source || !target) continue;

          ctx.beginPath();
          ctx.moveTo(source.x, source.y);
          ctx.lineTo(target.x, target.y);
          ctx.strokeStyle = link.singleSource ? '#ef4444' : '#334155';
          ctx.lineWidth = link.criticality === 'critical' ? 2 : 1;
          if (link.singleSource) {
            ctx.setLineDash([4, 4]);
          }
          ctx.stroke();
          ctx.setLineDash([]);
        }

        // Draw nodes
        for (const node of graphData.nodes) {
          const radius = node.tier === 'prime' ? 18 : node.tier === 'tier1' ? 14 : 10;
          const isHovered = hoveredNode === node.id;
          const isSelected = selectedNode === node.id;

          // Alert glow
          if (node.alertCount > 0) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, radius + 6, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(239, 68, 68, ${0.15 + node.alertCount * 0.05})`;
            ctx.fill();
          }

          // Node circle
          ctx.beginPath();
          ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
          ctx.fillStyle = isHovered || isSelected ? '#1e293b' : '#0f172a';
          ctx.fill();
          ctx.strokeStyle = tierColors[node.tier] || '#64748b';
          ctx.lineWidth = isHovered || isSelected ? 3 : 1.5;
          ctx.stroke();

          // Node label
          ctx.font = `${isHovered ? 'bold ' : ''}${node.tier === 'prime' ? 10 : 9}px Inter, sans-serif`;
          ctx.fillStyle = '#e2e8f0';
          ctx.textAlign = 'center';
          const shortName = node.name.length > 16 ? node.name.substring(0, 14) + '...' : node.name;
          ctx.fillText(shortName, node.x, node.y + radius + 14);
          ctx.textAlign = 'left';

          // Alert count badge
          if (node.alertCount > 0) {
            ctx.beginPath();
            ctx.arc(node.x + radius - 2, node.y - radius + 2, 7, 0, Math.PI * 2);
            ctx.fillStyle = '#ef4444';
            ctx.fill();
            ctx.font = 'bold 8px Inter, sans-serif';
            ctx.fillStyle = '#fff';
            ctx.textAlign = 'center';
            ctx.fillText(String(node.alertCount), node.x + radius - 2, node.y - radius + 5);
            ctx.textAlign = 'left';
          }
        }

        animFrameRef.current = requestAnimationFrame(draw);
      };

      draw();
      return () => cancelAnimationFrame(animFrameRef.current);
    }, [graphData, hoveredNode, selectedNode]);

    // Mouse interaction
    const handleCanvasMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      let found: string | null = null;
      for (const node of graphData.nodes) {
        const radius = node.tier === 'prime' ? 18 : node.tier === 'tier1' ? 14 : 10;
        const dx = x - node.x;
        const dy = y - node.y;
        if (dx * dx + dy * dy < radius * radius) {
          found = node.id;
          break;
        }
      }
      setHoveredNode(found);
    }, [graphData]);

    if (supplyChainMap.isLoading) return <LoadingState />;

    return (
      <div className="space-y-4">
        {/* Legend */}
        <div className="flex items-center gap-6 text-xs text-slate-400">
          <div className="flex items-center gap-4">
            <span className="font-medium text-slate-300">Tiers:</span>
            {Object.entries({ prime: '#a78bfa', tier1: '#60a5fa', tier2: '#22d3ee', tier3: '#94a3b8' }).map(([tier, color]) => (
              <span key={tier} className="flex items-center gap-1">
                <span className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
                {tier}
              </span>
            ))}
          </div>
          <div className="flex items-center gap-4">
            <span className="font-medium text-slate-300">Links:</span>
            <span className="flex items-center gap-1">
              <span className="w-6 h-0.5 bg-slate-600" />
              Normal
            </span>
            <span className="flex items-center gap-1">
              <span className="w-6 h-0.5 bg-red-500" style={{ borderTop: '2px dashed #ef4444' }} />
              Single Source Risk
            </span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-3 h-3 rounded-full bg-red-500/30" />
            Has Active Alerts
          </div>
        </div>

        {/* Graph Canvas */}
        <div className="bg-slate-900/80 border border-slate-700/50 rounded-lg overflow-hidden" style={{ height: '520px' }}>
          {graphData.nodes.length > 0 ? (
            <canvas
              ref={canvasRef}
              className="w-full h-full cursor-crosshair"
              onMouseMove={handleCanvasMove}
              onClick={() => setSelectedNode(hoveredNode)}
            />
          ) : (
            <EmptyState message="No supply chain relationships to visualize. Add suppliers and relationships first." />
          )}
        </div>

        {/* Selected Node Details */}
        {selectedNode && (() => {
          const node = graphData.nodes.find(n => n.id === selectedNode);
          if (!node) return null;
          const connections = graphData.links.filter(l => l.source === node.id || l.target === node.id);
          return (
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
              <div className="flex items-center gap-3 mb-3">
                <Building2 className="w-5 h-5 text-blue-400" />
                <div>
                  <div className="text-sm font-semibold text-white">{node.name}</div>
                  <div className="text-xs text-slate-400">{node.tier} • {node.sector}</div>
                </div>
                {node.alertCount > 0 && (
                  <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/10 text-red-400">
                    {node.alertCount} active alerts
                  </span>
                )}
              </div>
              <div className="text-xs text-slate-400 space-y-1">
                <div className="font-medium text-slate-300 mb-1">Connections ({connections.length}):</div>
                {connections.map((conn, i) => {
                  const otherId = conn.source === node.id ? conn.target : conn.source;
                  const other = graphData.nodes.find(n => n.id === otherId);
                  return (
                    <div key={i} className="flex items-center gap-2">
                      <ChevronRight className="w-3 h-3" />
                      <span className="text-slate-300">{other?.name || 'Unknown'}</span>
                      <span className="text-slate-500">— {conn.program}</span>
                      {conn.singleSource && <span className="text-red-400 font-medium">[SINGLE SOURCE]</span>}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })()}
      </div>
    );
  }

  // ─── Main Render ─────────────────────────────────────────────────────
  return (
    <AppShell>
      <div className="p-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Shield className="w-6 h-6 text-blue-400" />
              Supply Chain Threat Intelligence
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Monitor defense supplier exposure to emerging cyber threats
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-1 mb-6 border-b border-slate-700/50 pb-px">
          {[
            { id: "dashboard", label: "Dashboard", icon: BarChart3 },
            { id: "suppliers", label: "Suppliers", icon: Building2 },
            { id: "alerts", label: "Threat Alerts", icon: AlertTriangle },
            { id: "relationships", label: "Supply Chain", icon: Network },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium rounded-t-lg transition-colors ${
                activeTab === tab.id
                  ? "bg-slate-800/80 text-white border-b-2 border-blue-500"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/30"
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === "dashboard" && <DashboardView />}
        {activeTab === "suppliers" && <SuppliersView />}
        {activeTab === "alerts" && <AlertsView />}
        {activeTab === "relationships" && <RelationshipGraphView />}
      </div>
    </AppShell>
  );
}
