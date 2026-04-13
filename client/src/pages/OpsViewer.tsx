import { useState, useRef, useCallback, useEffect, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useOpsViewerLiveStream } from "@/hooks/useOpsViewerLiveStream";
import { useDIScanLiveStream } from "@/hooks/useDIScanLiveStream";
import { BattlespaceEngine, type EngineCallbacks, type EngineStats } from "@/lib/battlespace-engine";
import { transformEngagementGraph, transformDIScan } from "@/lib/battlespace-transform";
import type { BattlespaceNode, BattlespaceMode, ZoomLevel, KillChainPhase } from "@/lib/battlespace-types";
import { NODE_VISUAL_CONFIG, SEVERITY_COLORS, KILL_CHAIN_COLORS, EDGE_VISUAL_CONFIG } from "@/lib/battlespace-types";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { TimelineScrubber } from "@/components/TimelineScrubber";
import { VisualEffectToggles } from "@/components/VisualEffectToggles";
import type { EngineOptions } from "@/lib/battlespace-engine";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ZoomIn, ZoomOut, Maximize2, Crosshair, Layers, Shield, AlertTriangle,
  Activity, Eye, EyeOff, Target, Network, Skull, Radio, Lock,
  ChevronRight, X, Cpu, Globe, Server, Database, Cloud, Brain, Zap, Timer,
  ArrowLeft,
} from "lucide-react";
// wouter imports removed — back button uses window.history.back()

// ── Reasoning Status Indicator ─────────────────────────────────────
function ReasoningStatusBar({ reasoning, performance }: {
  reasoning?: { status: string; progress: number; hypothesesCount?: number };
  performance?: { loadTimeMs: number; source: string; dedup?: any; pruning?: any };
}) {
  if (!reasoning) return null;
  const { status, progress, hypothesesCount } = reasoning;

  return (
    <div className="absolute top-3 right-3 z-20 bg-[#0A0E14]/95 border border-[#1A2332] p-2 font-mono text-[9px] max-w-[240px]">
      <div className="flex items-center gap-2 mb-1">
        <Brain size={10} className={status === 'analyzing' ? 'text-amber-400 animate-pulse' : status === 'complete' ? 'text-teal-400' : 'text-gray-500'} />
        <span className="uppercase tracking-widest text-gray-400">
          {status === 'complete' ? 'REASONING COMPLETE' : status === 'analyzing' ? 'ANALYZING...' : 'FAST GRAPH'}
        </span>
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-[#111820] border border-[#1A2332] relative overflow-hidden mb-1.5">
        <div
          className="h-full transition-all duration-700"
          style={{
            width: `${progress}%`,
            background: status === 'complete'
              ? '#00E5CC'
              : 'linear-gradient(90deg, #00E5CC, #FFB800)',
          }}
        />
      </div>

      {/* Stats row */}
      <div className="flex items-center gap-2 text-gray-500">
        {performance && (
          <>
            <Zap size={8} className="text-teal-400" />
            <span>{performance.loadTimeMs}ms</span>
            <span className="text-gray-700">|</span>
            <span>{performance.source.toUpperCase()}</span>
          </>
        )}
        {performance?.dedup && performance.dedup.reductionPercent > 0 && (
          <>
            <span className="text-gray-700">|</span>
            <span className="text-amber-400">-{performance.dedup.reductionPercent}% DEDUP</span>
          </>
        )}
      </div>

      {hypothesesCount != null && hypothesesCount > 0 && (
        <div className="flex items-center gap-1 mt-1 text-teal-400">
          <Brain size={8} />
          <span>{hypothesesCount} HYPOTHESES</span>
        </div>
      )}
    </div>
  );
}

// ── Stats HUD ───────────────────────────────────────────────────────
function StatsHUD({ stats, mode }: { stats: EngineStats | null; mode: BattlespaceMode }) {
  if (!stats) return null;
  return (
    <div className="absolute top-3 left-3 z-20 font-mono text-[10px] tracking-wider uppercase text-gray-500 space-y-0.5 select-none pointer-events-none">
      <div className="flex items-center gap-2">
        <span className="text-teal-400">{mode === "engagement" ? "ENGAGEMENT" : "DI SCAN"}</span>
        <span className="text-gray-600">|</span>
        <span>{stats.fps} FPS</span>
      </div>
      <div className="flex items-center gap-2">
        <span>{stats.nodeCount} NODES</span>
        <span className="text-gray-600">|</span>
        <span>{stats.edgeCount} EDGES</span>
        {stats.clusterCount > 0 && (
          <><span className="text-gray-600">|</span><span className="text-blue-400">{stats.clusterCount} CLUSTERS</span></>
        )}
        <span className="text-gray-600">|</span>
        <span>α {stats.simulationAlpha.toFixed(3)}</span>
      </div>
      <div className="flex items-center gap-2">
        <span>ZOOM: {stats.zoomLevel}</span>
        <span className="text-gray-600">|</span>
        <span>{(stats.scale * 100).toFixed(0)}%</span>
      </div>
    </div>
  );
}

// ── Node Detail Panel ───────────────────────────────────────────────
function NodeDetailPanel({
  node,
  onClose,
}: {
  node: BattlespaceNode | null;
  onClose: () => void;
}) {
  if (!node) return null;
  const config = NODE_VISUAL_CONFIG[node.type] || NODE_VISUAL_CONFIG.host;
  const sevColor = node.severity ? SEVERITY_COLORS[node.severity] : config.strokeColor;

  return (
    <div className="absolute right-3 top-3 z-30 w-80 bg-[#0A0E14] border border-[#1A2332] font-mono text-xs">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-[#1A2332]" style={{ borderLeftColor: sevColor, borderLeftWidth: 3 }}>
        <div className="flex items-center gap-2">
          <span className="text-lg">{config.icon}</span>
          <div>
            <div className="text-[10px] uppercase tracking-widest text-gray-500">{node.type.replace("_", " ")}</div>
            <div className="text-white font-bold truncate max-w-[200px]">{node.label}</div>
          </div>
        </div>
        <button onClick={onClose} className="text-gray-500 hover:text-white p-1"><X size={14} /></button>
      </div>

      {/* Body */}
      <div className="p-3 space-y-3 max-h-[60vh] overflow-y-auto">
        {/* Severity + Priority */}
        <div className="grid grid-cols-2 gap-2">
          <div className="bg-[#111820] p-2 border border-[#1A2332]">
            <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-1">SEVERITY</div>
            <div className="font-bold uppercase" style={{ color: sevColor }}>{node.severity || "N/A"}</div>
          </div>
          <div className="bg-[#111820] p-2 border border-[#1A2332]">
            <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-1">PRIORITY</div>
            <div className="font-bold text-white">{((node.priorityScore || 0) * 100).toFixed(0)}%</div>
          </div>
        </div>

        {/* Weakness Level Bar */}
        {node.weaknessLevel != null && (
          <div>
            <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-1">WEAKNESS LEVEL</div>
            <div className="h-2 bg-[#111820] border border-[#1A2332] relative overflow-hidden">
              <div
                className="h-full transition-all duration-500"
                style={{
                  width: `${(node.weaknessLevel || 0) * 100}%`,
                  background: `linear-gradient(90deg, #00E5CC, #FFB800, #FF0040)`,
                }}
              />
            </div>
          </div>
        )}

        {/* Host Info */}
        {node.hostname && (
          <div className="bg-[#111820] p-2 border border-[#1A2332]">
            <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-1">HOST</div>
            <div className="text-teal-400">{node.hostname}</div>
            {node.ip && <div className="text-gray-400 mt-0.5">{node.ip}</div>}
            {node.os && <div className="text-gray-400 mt-0.5">{node.os}</div>}
          </div>
        )}

        {/* Service */}
        {node.serviceName && (
          <div className="bg-[#111820] p-2 border border-[#1A2332]">
            <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-1">SERVICE</div>
            <div className="text-blue-400">{node.serviceName}{node.port ? `:${node.port}` : ""}</div>
            {node.version && <div className="text-gray-400 mt-0.5">v{node.version}</div>}
          </div>
        )}

        {/* Technologies */}
        {node.technologies && node.technologies.length > 0 && (
          <div>
            <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-1">TECH STACK</div>
            <div className="flex flex-wrap gap-1">
              {node.technologies.map((t, i) => (
                <span key={i} className="px-1.5 py-0.5 bg-[#111820] border border-[#2D4A6F] text-[9px] uppercase tracking-wider text-gray-300">{t}</span>
              ))}
            </div>
          </div>
        )}

        {/* MITRE ATT&CK */}
        {node.mitreIds && node.mitreIds.length > 0 && (
          <div>
            <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-1">MITRE ATT&CK</div>
            <div className="flex flex-wrap gap-1">
              {node.mitreIds.map((id, i) => (
                <span key={i} className="px-1.5 py-0.5 bg-[#2A0A0A] border border-[#FF0040] text-[9px] text-red-400">{id}</span>
              ))}
            </div>
          </div>
        )}

        {/* Platform */}
        {node.platform && node.platform !== "unknown" && (
          <div className="bg-[#111820] p-2 border border-[#1A2332]">
            <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-1">PLATFORM</div>
            <div className="text-purple-400 uppercase">{node.platform}</div>
          </div>
        )}

        {/* Kill Chain Phase */}
        {node.killChainPhase && (
          <div className="bg-[#111820] p-2 border border-[#1A2332]">
            <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-1">KILL CHAIN PHASE</div>
            <div style={{ color: KILL_CHAIN_COLORS[node.killChainPhase] }} className="uppercase font-bold">{node.killChainPhase}</div>
          </div>
        )}

        {/* Defense Info */}
        {node.defenseType && (
          <div className="bg-[#0A1628] p-2 border border-[#3B82F6]">
            <div className="text-[9px] uppercase tracking-widest text-blue-400 mb-1">DEFENSE ASSET</div>
            <div className="text-blue-300 uppercase font-bold">{node.defenseType}</div>
            {node.ruleCount != null && <div className="text-gray-400 mt-0.5">{node.ruleCount} active rules</div>}
          </div>
        )}

        {/* Threat Actor Info */}
        {node.threatGroupId && (
          <div className="bg-[#2A0A0A] p-2 border border-[#FF0040]">
            <div className="text-[9px] uppercase tracking-widest text-red-400 mb-1">THREAT ACTOR</div>
            <div className="text-red-300 font-bold">{node.label}</div>
            {node.threatLevel && <div className="text-gray-400 mt-0.5 uppercase">{node.threatLevel} threat</div>}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Legend Panel ─────────────────────────────────────────────────────
function LegendPanel({ visible }: { visible: boolean }) {
  if (!visible) return null;

  const nodeTypes = [
    { type: "host", label: "Host/Server" },
    { type: "domain", label: "Domain" },
    { type: "vulnerability", label: "Vulnerability" },
    { type: "hypothesis", label: "Hypothesis" },
    { type: "defense", label: "Defense Asset" },
    { type: "threat_actor", label: "Threat Actor" },
    { type: "agent", label: "C2 Agent" },
    { type: "credential", label: "Credential" },
    { type: "crown_jewel", label: "Crown Jewel" },
    { type: "ioc", label: "IOC" },
    { type: "data_asset", label: "Data Asset" },
    { type: "cloud_resource", label: "Cloud Resource" },
  ] as const;

  const edgeTypes = [
    { type: "exploits", label: "Exploits" },
    { type: "enables", label: "Enables" },
    { type: "pivots_to", label: "Lateral Move" },
    { type: "protects", label: "Protects" },
    { type: "targets", label: "Targets" },
    { type: "data_flow", label: "Data Flow" },
  ] as const;

  return (
    <div className="absolute bottom-3 left-3 z-20 bg-[#0A0E14]/95 border border-[#1A2332] p-3 font-mono text-[9px] max-w-[280px] max-h-[50vh] overflow-y-auto">
      <div className="uppercase tracking-widest text-gray-500 mb-2 text-[10px] font-bold">SYMBOLOGY</div>

      {/* Node types */}
      <div className="space-y-1 mb-3">
        {nodeTypes.map(({ type, label }) => {
          const config = NODE_VISUAL_CONFIG[type];
          return (
            <div key={type} className="flex items-center gap-2">
              <div className="w-4 h-4 flex items-center justify-center text-[10px]" style={{ color: config.strokeColor }}>{config.icon}</div>
              <span className="text-gray-400 uppercase tracking-wider">{label}</span>
            </div>
          );
        })}
      </div>

      {/* Severity */}
      <div className="uppercase tracking-widest text-gray-500 mb-1 text-[10px] font-bold">SEVERITY</div>
      <div className="flex gap-1 mb-3">
        {(Object.entries(SEVERITY_COLORS) as [string, string][]).map(([sev, color]) => (
          <div key={sev} className="flex items-center gap-1">
            <div className="w-2 h-2" style={{ backgroundColor: color }} />
            <span className="text-gray-500 uppercase" style={{ fontSize: "8px" }}>{sev.slice(0, 4)}</span>
          </div>
        ))}
      </div>

      {/* Edge types */}
      <div className="uppercase tracking-widest text-gray-500 mb-1 text-[10px] font-bold">CONNECTIONS</div>
      <div className="space-y-1">
        {edgeTypes.map(({ type, label }) => {
          const config = EDGE_VISUAL_CONFIG[type];
          return (
            <div key={type} className="flex items-center gap-2">
              <div className="w-8 h-0.5" style={{ backgroundColor: config.color }} />
              <span className="text-gray-400 uppercase tracking-wider">{label}</span>
            </div>
          );
        })}
      </div>

      {/* Kill Chain */}
      <div className="uppercase tracking-widest text-gray-500 mb-1 mt-3 text-[10px] font-bold">KILL CHAIN</div>
      <div className="flex gap-0.5">
        {(Object.entries(KILL_CHAIN_COLORS) as [string, string][]).map(([phase, color]) => (
          <div key={phase} className="flex-1 h-3 relative group" style={{ backgroundColor: color }}>
            <div className="absolute -bottom-3 left-0 text-[7px] text-gray-500 uppercase hidden group-hover:block">{phase}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Attack Path Selector ────────────────────────────────────────────
function PathSelector({
  paths,
  selectedPath,
  onSelect,
}: {
  paths: any[];
  selectedPath: number | null;
  onSelect: (idx: number | null) => void;
}) {
  if (!paths || paths.length === 0) return null;

  return (
    <div className="absolute bottom-3 right-3 z-20 bg-[#0A0E14]/95 border border-[#1A2332] p-3 font-mono text-xs max-w-[320px] max-h-[40vh] overflow-y-auto">
      <div className="text-[10px] uppercase tracking-widest text-gray-500 mb-2 font-bold">ATTACK PATHS ({paths.length})</div>
      <div className="space-y-1.5">
        {paths.map((path: any, i: number) => (
          <button
            key={i}
            onClick={() => onSelect(selectedPath === i ? null : i)}
            className={`w-full text-left p-2 border transition-colors ${
              selectedPath === i
                ? "border-[#FF0040] bg-[#2A0A0A]"
                : "border-[#1A2332] bg-[#111820] hover:border-[#2D4A6F]"
            }`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-white font-bold truncate">{path.name || `Path ${i + 1}`}</span>
              <span className="text-[9px] uppercase px-1.5 py-0.5 border" style={{
                color: path.feasibility > 0.7 ? "#FF0040" : path.feasibility > 0.4 ? "#FFB800" : "#00E5CC",
                borderColor: path.feasibility > 0.7 ? "#FF0040" : path.feasibility > 0.4 ? "#FFB800" : "#00E5CC",
              }}>
                {(path.feasibility * 100).toFixed(0)}% FEASIBLE
              </span>
            </div>
            <div className="text-gray-500 text-[9px] truncate">{path.description}</div>
            <div className="flex items-center gap-2 mt-1 text-[8px] text-gray-600">
              <span>{path.steps?.length || path.nodeIds?.length || 0} STEPS</span>
              <span>|</span>
              <span>IMPACT {((path.impact || 0) * 100).toFixed(0)}%</span>
              {path.opsecRisk && <><span>|</span><span>OPSEC {path.opsecRisk.toUpperCase()}</span></>}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Main Ops Viewer Component ──────────────────────────────────────────────────────
export default function Battlespace() {
  const containerRef = useRef<HTMLDivElement>(null);
  const engineRef = useRef<BattlespaceEngine | null>(null);

  // Read ?eid= and ?di= query params for deep-linking
  const [initialEid] = useState(() => {
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      return params.get('eid') || '';
    }
    return '';
  });
  const [initialDi] = useState(() => {
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      return params.get('di') || '';
    }
    return '';
  });

  // Store the referrer page so the back button returns to the correct origin
  const [backPath] = useState(() => {
    if (typeof window !== 'undefined') {
      // Check if the browser has a real history entry we can go back to
      // document.referrer gives us the previous page URL within the SPA
      const params = new URLSearchParams(window.location.search);
      const from = params.get('from');
      if (from) return from;
      // Fallback: infer from the query params
      if (params.get('di')) return '/domain-intel';
      if (params.get('eid')) return '/engagements';
    }
    return '/';
  });

  // State
  const [mode, setMode] = useState<BattlespaceMode>(initialDi ? "di_scan" : "engagement");
  const [engagementId, setEngagementId] = useState<string>(initialEid);
  const [diScanId, setDiScanId] = useState<string>(initialDi);
  const [stats, setStats] = useState<EngineStats | null>(null);
  const [selectedNode, setSelectedNode] = useState<BattlespaceNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<{ node: BattlespaceNode; x: number; y: number } | null>(null);
  const [showLegend, setShowLegend] = useState(true);
  const [selectedPath, setSelectedPath] = useState<number | null>(null);
  const [showTopologyFilters, setShowTopologyFilters] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showClusters, setShowClusters] = useState(true);
  const [topologyLayers, setTopologyLayers] = useState<Record<string, boolean>>({
    proxy: true,
    gateway: true,
    c2_server: true,
    tap_point: true,
  });

  // Timeline scrubber state
  const [timeRange, setTimeRange] = useState<{ min: number; max: number } | null>(null);
  const [visibleNodeCount, setVisibleNodeCount] = useState(0);
  const [totalNodeCount, setTotalNodeCount] = useState(0);

  // Visual effect toggles state
  const [engineOptions, setEngineOptions] = useState<Partial<EngineOptions>>({});

  // Data queries
  const engagementsQuery = trpc.engagements.list.useQuery(undefined, { retry: 1 });
  const engagements = engagementsQuery.data || [];

  // ── OPTIMIZATION: Use getGraphFast for instant load, poll for reasoning ──
  const parsedEngagementId = parseInt(engagementId);
  const engagementEnabled = mode === "engagement" && !!engagementId && !isNaN(parsedEngagementId);

  const graphQuery = trpc.exploitAttackGraph.getGraphFast.useQuery(
    { engagementId: parsedEngagementId },
    { enabled: engagementEnabled, retry: 1 }
  );

  // Poll for reasoning results when status is 'analyzing'
  const reasoningStatus = graphQuery.data?.reasoning?.status;
  const reasoningQuery = trpc.exploitAttackGraph.getReasoningResults.useQuery(
    { engagementId: parsedEngagementId },
    {
      enabled: engagementEnabled && (reasoningStatus === 'analyzing' || reasoningStatus === 'pending'),
      refetchInterval: reasoningStatus === 'analyzing' ? 3000 : false,
      retry: 1,
    }
  );

  // Merge reasoning results into graph when they arrive
  const [reasoningMerged, setReasoningMerged] = useState(false);
  useEffect(() => {
    if (reasoningQuery.data?.status === 'complete' && !reasoningMerged && engineRef.current) {
      const rd = reasoningQuery.data;
      if (rd.nodes && rd.nodes.length > 0) {
        // Reasoning returned enriched graph — reload with full data
        const graphData = transformEngagementGraph({
          nodes: rd.nodes,
          edges: rd.edges,
          paths: rd.paths,
        });
        engineRef.current.loadGraph(graphData);
        setTimeout(() => engineRef.current?.fitToView(), 500);
        setReasoningMerged(true);
      }
    }
  }, [reasoningQuery.data, reasoningMerged]);

  // Reset reasoning merge flag when engagement changes
  useEffect(() => {
    setReasoningMerged(false);
  }, [engagementId]);

  // DI scan queries
  const diScansQuery = trpc.domainIntel.listScans.useQuery(undefined, { retry: 1 });
  const diScans = diScansQuery?.data || [];

  // Engine state — declared before hooks that reference engineReady
  const [engineReady, setEngineReady] = useState(false);
  const [engineError, setEngineError] = useState<string | null>(null);

  // Ember C2 + OPSEC events — lightweight hook for engine.processWsEvent
  // (Recon/exploit/agent events are handled by useOpsViewerLiveStream)
  const emberFilterTypes = useMemo<import("@/hooks/useWebSocket").WsEventType[]>(() => [
    "opsec:action_scored",
    "opsec:burn_detected",
    "c2:agent_checkin",
    "c2:ability_executed",
    "c2:operation_update",
  ], []);
  const emberWs = useWebSocket({
    filterTypes: emberFilterTypes,
    maxEvents: 20,
    showToasts: false,
    enabled: mode === "engagement" && engineReady,
  });

  // Engine callbacks
  const callbacks = useMemo<EngineCallbacks>(() => ({
    onNodeHover: (node, x, y) => {
      if (node) setHoveredNode({ node, x, y });
      else setHoveredNode(null);
    },
    onNodeClick: (node) => setSelectedNode(node),
    onZoomChange: (_scale, _level) => {},
    onStatsUpdate: (s) => setStats(s),
  }), []);

  useEffect(() => {
    if (!containerRef.current) return;
    let cancelled = false;
    const engine = new BattlespaceEngine(callbacks);
    engineRef.current = engine;

    engine.init(containerRef.current)
      .then(() => {
        if (!cancelled) setEngineReady(true);
      })
      .catch((err) => {
        console.error("[OpsViewer] Engine init failed:", err);
        if (!cancelled) setEngineError(err?.message || "WebGL initialization failed");
      });

    const handleResize = () => {
      if (containerRef.current) {
        engine.resize(containerRef.current.clientWidth, containerRef.current.clientHeight);
      }
    };
    window.addEventListener("resize", handleResize);

    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement || !!(document as any).webkitFullscreenElement);
      // Resize canvas after fullscreen transition
      setTimeout(() => {
        if (containerRef.current) {
          engine.resize(containerRef.current.clientWidth, containerRef.current.clientHeight);
        }
      }, 100);
    };
    document.addEventListener("fullscreenchange", handleFullscreenChange);
    document.addEventListener("webkitfullscreenchange", handleFullscreenChange);

    return () => {
      cancelled = true;
      window.removeEventListener("resize", handleResize);
      document.removeEventListener("fullscreenchange", handleFullscreenChange);
      document.removeEventListener("webkitfullscreenchange", handleFullscreenChange);
      engine.destroy();
      engineRef.current = null;
      setEngineReady(false);
    };
  }, [callbacks]);

  // Load graph data when engagement changes
  useEffect(() => {
    if (!engineRef.current || !graphQuery.data) return;
    const graphData = transformEngagementGraph(graphQuery.data);
    engineRef.current.loadGraph(graphData);
    setTimeout(() => {
      engineRef.current?.fitToView();
      // Compute time range for timeline scrubber
      const range = engineRef.current?.getTimeRange() || null;
      setTimeRange(range);
      setTotalNodeCount(graphData.nodes.length);
      setVisibleNodeCount(graphData.nodes.length);
      // Sync engine options to state
      if (engineRef.current) setEngineOptions({ ...engineRef.current.getOptions() });
    }, 600);
  }, [graphQuery.data]);

  // Timeline scrubber callback
  const handleTimeChange = useCallback((startMs: number | null, endMs: number | null) => {
    if (!engineRef.current) return;
    engineRef.current.setTimeWindow(startMs, endMs);
    // Count visible nodes
    if (startMs == null && endMs == null) {
      setVisibleNodeCount(totalNodeCount);
    } else {
      // Approximate: count nodes with discoveredAt <= endMs
      const range = engineRef.current.getTimeRange();
      if (range && endMs != null) {
        const pct = Math.max(0, Math.min(1, (endMs - range.min) / (range.max - range.min)));
        setVisibleNodeCount(Math.round(pct * totalNodeCount));
      }
    }
  }, [totalNodeCount]);

  // Visual effect toggle callback
  const handleToggle = useCallback((key: keyof EngineOptions, value: boolean) => {
    if (!engineRef.current) return;
    engineRef.current.setOption(key, value as any);
    setEngineOptions(prev => ({ ...prev, [key]: value }));
  }, []);

  // ── Real-time progressive rendering via useOpsViewerLiveStream ──────
  const [liveEventCount, setLiveEventCount] = useState(0);
  const [currentPhase, setCurrentPhase] = useState<string | null>(null);

  const handleLiveNodesDiscovered = useCallback((newNodes: BattlespaceNode[], newEdges: any[]) => {
    if (!engineRef.current) return;
    engineRef.current.addNodes(newNodes, newEdges);
  }, []);

  const handlePhaseChanged = useCallback((phase: string, _prev: string) => {
    setCurrentPhase(phase);
  }, []);

  const handleEventCount = useCallback((count: number) => {
    setLiveEventCount(count);
  }, []);

  const { isConnected: liveStreamConnected } = useOpsViewerLiveStream({
    engagementId: engagementEnabled ? parsedEngagementId : null,
    onNodesDiscovered: handleLiveNodesDiscovered,
    onPhaseChanged: handlePhaseChanged,
    onEventCount: handleEventCount,
    enabled: mode === "engagement" && engineReady,
  });

  // ── DI Scan data loading + live stream ──────────────────────────────
  const parsedDiScanId = parseInt(diScanId);
  const diScanEnabled = mode === "di_scan" && !!diScanId && !isNaN(parsedDiScanId);

  const diScanQuery = trpc.domainIntel.getScan.useQuery(
    { id: parsedDiScanId },
    { enabled: diScanEnabled, retry: 1 }
  );

  // Load DI scan data into the engine
  useEffect(() => {
    if (!engineRef.current || !diScanQuery.data) return;
    const { scan, assets } = diScanQuery.data;
    const graphData = transformDIScan(scan, assets);
    engineRef.current.loadGraph(graphData);
    setTimeout(() => engineRef.current?.fitToView(), 600);
  }, [diScanQuery.data]);

  // DI scan live stream state
  const [diLiveEventCount, setDiLiveEventCount] = useState(0);
  const [diCurrentStage, setDiCurrentStage] = useState<string | null>(null);
  const [diScanComplete, setDiScanComplete] = useState(false);

  const handleDiNodesDiscovered = useCallback((newNodes: BattlespaceNode[], newEdges: any[]) => {
    if (!engineRef.current) return;
    engineRef.current.addNodes(newNodes, newEdges);
  }, []);

  const handleDiStageChanged = useCallback((stage: string, _prev: string) => {
    setDiCurrentStage(stage);
  }, []);

  const handleDiEventCount = useCallback((count: number) => {
    setDiLiveEventCount(count);
  }, []);

  const handleDiScanComplete = useCallback((_data: { totalAssets: number; totalFindings: number; overallRiskScore: number }) => {
    setDiScanComplete(true);
    // Refresh the scan data to get the final state
    diScanQuery.refetch();
  }, [diScanQuery]);

  const diScanDomain = diScanQuery.data?.scan?.primaryDomain;

  const { isConnected: diLiveStreamConnected } = useDIScanLiveStream({
    scanId: diScanEnabled ? parsedDiScanId : null,
    domain: diScanDomain,
    onNodesDiscovered: handleDiNodesDiscovered,
    onStageChanged: handleDiStageChanged,
    onEventCount: handleDiEventCount,
    onScanComplete: handleDiScanComplete,
    enabled: mode === "di_scan" && engineReady,
  });

  // Reset DI live state when scan changes
  useEffect(() => {
    setDiLiveEventCount(0);
    setDiCurrentStage(null);
    setDiScanComplete(false);
  }, [diScanId]);

  // Route OPSEC/C2 events through the engine's unified handler
  // Uses lastEvent (stable reference) instead of events array to avoid re-processing
  useEffect(() => {
    const latest = emberWs.lastEvent;
    if (!latest?.data || !engineRef.current) return;

    // OPSEC events → flash relevant Ember nodes
    if (latest.type === "opsec:action_scored") {
      const action = latest.data.action || "";
      if (action.startsWith("ember:")) {
        engineRef.current.processWsEvent({
          type: "ember:opsec_scored",
          data: { ...latest.data, agentId: action.split(":")[1] },
        });
      }
    }
    // C2 events → route to engine
    if (latest.type.startsWith("c2:")) {
      engineRef.current.processWsEvent({ type: latest.type, data: latest.data });
    }
  }, [emberWs.lastEvent]);

  // Handle path highlighting — uses reasoning paths if available
  const activePaths = reasoningMerged && reasoningQuery.data?.paths
    ? reasoningQuery.data.paths
    : (graphQuery.data?.paths || []);

  useEffect(() => {
    if (!engineRef.current || activePaths.length === 0) return;
    if (selectedPath != null && activePaths[selectedPath]) {
      const path = activePaths[selectedPath];
      engineRef.current.highlightPath(path.nodeIds || path.steps?.map((s: any) => s.nodeId) || []);
    } else {
      engineRef.current.clearHighlight();
    }
  }, [selectedPath, activePaths]);

  return (
      <div className="h-screen flex flex-col bg-[#0A0E14] overflow-hidden">
        {/* Top Bar */}
        <div className="h-12 border-b border-[#1A2332] flex items-center px-4 gap-3 shrink-0">
          {/* Back to Dashboard — always visible */}
          <button onClick={() => { if (window.history.length > 1) { window.history.back(); } else { window.location.href = backPath; } }} className="flex items-center gap-1 text-[10px] uppercase tracking-wider font-mono text-gray-400 hover:text-teal-400 transition-colors pr-2 border-r border-[#1A2332] bg-transparent border-0 cursor-pointer">
            <ArrowLeft size={12} />
            <span>Back</span>
          </button>
          <div className="flex items-center gap-2">
            <Crosshair size={16} className="text-teal-400" />
            <span className="font-mono text-xs uppercase tracking-widest text-white font-bold">OPS VIEWER</span>
          </div>

          <div className="h-6 w-px bg-[#1A2332]" />

          {/* Mode Toggle */}
          <Tabs value={mode} onValueChange={(v) => setMode(v as BattlespaceMode)}>
            <TabsList className="h-7 bg-[#111820] border border-[#1A2332] rounded-none">
              <TabsTrigger value="engagement" className="text-[10px] uppercase tracking-wider rounded-none h-5 px-2 data-[state=active]:bg-[#1A2332] data-[state=active]:text-teal-400">
                <Target size={10} className="mr-1" /> ENGAGEMENT
              </TabsTrigger>
              <TabsTrigger value="di_scan" className="text-[10px] uppercase tracking-wider rounded-none h-5 px-2 data-[state=active]:bg-[#1A2332] data-[state=active]:text-teal-400">
                <Globe size={10} className="mr-1" /> DI SCAN
              </TabsTrigger>
            </TabsList>
          </Tabs>

          <div className="h-6 w-px bg-[#1A2332]" />

          {/* Engagement/Scan Selector */}
          {mode === "engagement" ? (
            <Select value={engagementId} onValueChange={setEngagementId}>
              <SelectTrigger className="w-52 h-7 bg-[#111820] border-[#1A2332] rounded-none text-[10px] uppercase tracking-wider font-mono">
                <SelectValue placeholder="SELECT ENGAGEMENT" />
              </SelectTrigger>
              <SelectContent className="bg-[#0A0E14] border-[#1A2332] rounded-none">
                {engagements.map((e: any) => (
                  <SelectItem key={e.id} value={String(e.id)} className="text-[10px] uppercase tracking-wider font-mono">
                    {e.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <Select value={diScanId} onValueChange={setDiScanId}>
              <SelectTrigger className="w-52 h-7 bg-[#111820] border-[#1A2332] rounded-none text-[10px] uppercase tracking-wider font-mono">
                <SelectValue placeholder="SELECT DI SCAN" />
              </SelectTrigger>
              <SelectContent className="bg-[#0A0E14] border-[#1A2332] rounded-none">
                {Array.isArray(diScans) && diScans.map((s: any) => (
                  <SelectItem key={s.id} value={String(s.id)} className="text-[10px] uppercase tracking-wider font-mono">
                    {s.primaryDomain}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}

          {/* Active engagement/scan name display */}
          {mode === "engagement" && engagementId && (() => {
            const eng = engagements.find((e: any) => String(e.id) === engagementId);
            return eng ? (
              <div className="flex items-center gap-2 px-2 border-l border-[#1A2332]">
                <Target size={10} className="text-red-400" />
                <span className="text-[10px] font-mono uppercase tracking-wider text-gray-300">{eng.name}</span>
                {eng.targetDomain && <span className="text-[9px] font-mono text-gray-500">({eng.targetDomain})</span>}
              </div>
            ) : null;
          })()}
          {mode === "di_scan" && diScanId && (() => {
            const scan = Array.isArray(diScans) && diScans.find((s: any) => String(s.id) === diScanId);
            return scan ? (
              <div className="flex items-center gap-2 px-2 border-l border-[#1A2332]">
                <Globe size={10} className="text-teal-400" />
                <span className="text-[10px] font-mono uppercase tracking-wider text-gray-300">{scan.primaryDomain}</span>
              </div>
            ) : null;
          })()}

          {/* Live Stream Status Indicator */}
          {mode === "engagement" && engagementId && (
            <div className="flex items-center gap-2 px-2 border-l border-[#1A2332]">
              <div className={`w-2 h-2 rounded-full ${liveStreamConnected ? 'bg-green-500 animate-pulse' : 'bg-gray-600'}`} />
              <span className="text-[9px] font-mono uppercase tracking-wider text-gray-400">
                {liveStreamConnected ? 'LIVE' : 'OFFLINE'}
              </span>
              {liveEventCount > 0 && (
                <span className="text-[9px] font-mono text-teal-400">{liveEventCount} events</span>
              )}
              {currentPhase && (
                <span className="text-[9px] font-mono text-amber-400 truncate max-w-[120px]">{currentPhase}</span>
              )}
            </div>
          )}
          {/* DI Scan Live Stream Status Indicator */}
          {mode === "di_scan" && diScanId && (
            <div className="flex items-center gap-2 px-2 border-l border-[#1A2332]">
              <div className={`w-2 h-2 rounded-full ${diLiveStreamConnected ? 'bg-teal-500 animate-pulse' : diScanComplete ? 'bg-blue-500' : 'bg-gray-600'}`} />
              <span className="text-[9px] font-mono uppercase tracking-wider text-gray-400">
                {diScanComplete ? 'COMPLETE' : diLiveStreamConnected ? 'LIVE' : 'OFFLINE'}
              </span>
              {diLiveEventCount > 0 && (
                <span className="text-[9px] font-mono text-teal-400">{diLiveEventCount} events</span>
              )}
              {diCurrentStage && !diScanComplete && (
                <span className="text-[9px] font-mono text-amber-400 truncate max-w-[120px]">{diCurrentStage}</span>
              )}
            </div>
          )}

          <div className="flex-1" />

          {/* Toolbar */}
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="sm"
              className="h-7 w-7 p-0 rounded-none border-[#1A2332] bg-transparent hover:bg-[#1A2332]"
              onClick={() => engineRef.current?.zoomIn()}
            >
              <ZoomIn size={12} />
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 w-7 p-0 rounded-none border-[#1A2332] bg-transparent hover:bg-[#1A2332]"
              onClick={() => engineRef.current?.zoomOut()}
            >
              <ZoomOut size={12} />
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 w-7 p-0 rounded-none border-[#1A2332] bg-transparent hover:bg-[#1A2332]"
              onClick={() => engineRef.current?.fitToView()}
              title="Fit to View"
            >
              <Maximize2 size={12} />
            </Button>
            <Button
              variant="outline"
              size="sm"
              className={`h-7 w-7 p-0 rounded-none border-[#1A2332] ${isFullscreen ? 'bg-[#1A2332] text-teal-400' : 'bg-transparent'}`}
              onClick={() => {
                if (isFullscreen) {
                  engineRef.current?.exitFullscreen();
                  setIsFullscreen(false);
                } else {
                  engineRef.current?.requestFullscreen();
                  setIsFullscreen(true);
                }
              }}
              title="Toggle Fullscreen"
            >
              <Crosshair size={12} />
            </Button>
            <div className="h-6 w-px bg-[#1A2332]" />
            <Button
              variant="outline"
              size="sm"
              className={`h-7 w-7 p-0 rounded-none border-[#1A2332] ${showClusters ? 'bg-[#1A2332] text-blue-400' : 'bg-transparent'}`}
              onClick={() => {
                const next = !showClusters;
                setShowClusters(next);
                engineRef.current?.setClustersEnabled(next);
              }}
              title="Toggle Cluster Grouping"
            >
              <Database size={12} />
            </Button>
            <Button
              variant="outline"
              size="sm"
              className={`h-7 w-7 p-0 rounded-none border-[#1A2332] ${showLegend ? "bg-[#1A2332] text-teal-400" : "bg-transparent"}`}
              onClick={() => setShowLegend(!showLegend)}
              title="Toggle Legend"
            >
              <Layers size={12} />
            </Button>
            <Button
              variant="outline"
              size="sm"
              className={`h-7 w-7 p-0 rounded-none border-[#1A2332] ${showTopologyFilters ? "bg-[#1A2332] text-orange-400" : "bg-transparent"}`}
              onClick={() => setShowTopologyFilters(!showTopologyFilters)}
              title="Network Topology Filters"
            >
              <Network size={12} />
            </Button>
            <div className="h-6 w-px bg-[#1A2332]" />
            <VisualEffectToggles options={engineOptions} onToggle={handleToggle} />
          </div>
        </div>

        {/* Canvas Area */}
        <div className="flex-1 relative">
          {/* Loading state — now shows fast-load progress */}
          {graphQuery.isLoading && (
            <div className="absolute inset-0 z-40 flex items-center justify-center bg-[#0A0E14]/80">
              <div className="font-mono text-xs uppercase tracking-widest text-teal-400 flex flex-col items-center gap-2">
                <Zap size={14} className="animate-pulse" />
                <span>FAST-LOADING ATTACK GRAPH...</span>
                <span className="text-[9px] text-gray-500">Deterministic build — no LLM wait</span>
              </div>
            </div>
          )}

          {/* Empty state — engagement mode */}
          {!engagementId && mode === "engagement" && (
            <div className="absolute inset-0 z-30 flex items-center justify-center">
              <div className="text-center font-mono">
                <Crosshair size={48} className="text-[#1A2332] mx-auto mb-4" />
                <div className="text-xs uppercase tracking-widest text-gray-600 mb-1">NO TARGET SELECTED</div>
                <div className="text-[10px] text-gray-700">Select an engagement to visualize the attack surface</div>
              </div>
            </div>
          )}

          {/* Empty state — DI scan mode */}
          {!diScanId && mode === "di_scan" && (
            <div className="absolute inset-0 z-30 flex items-center justify-center">
              <div className="text-center font-mono">
                <Globe size={48} className="text-[#1A2332] mx-auto mb-4" />
                <div className="text-xs uppercase tracking-widest text-gray-600 mb-1">NO SCAN SELECTED</div>
                <div className="text-[10px] text-gray-700">Select a DI scan to visualize discovered assets</div>
              </div>
            </div>
          )}

          {/* Empty graph state — engagement selected but no data */}
          {engagementId && mode === "engagement" && !graphQuery.isLoading && graphQuery.data && graphQuery.data.nodes?.length === 0 && (
            <div className="absolute inset-0 z-30 flex items-center justify-center">
              <div className="text-center font-mono">
                <AlertTriangle size={48} className="text-amber-500/30 mx-auto mb-4" />
                <div className="text-xs uppercase tracking-widest text-amber-500/60 mb-1">NO GRAPH DATA</div>
                <div className="text-[10px] text-gray-700 max-w-xs">This engagement has no findings yet. Run scans or exploits to populate the attack graph.</div>
                <div className="text-[9px] text-gray-600 mt-2">Live events will render automatically when available.</div>
              </div>
            </div>
          )}

          {/* Empty graph state — DI scan selected but no assets */}
          {diScanId && mode === "di_scan" && !diScanQuery.isLoading && diScanQuery.data && diScanQuery.data.assets?.length === 0 && (
            <div className="absolute inset-0 z-30 flex items-center justify-center">
              <div className="text-center font-mono">
                <AlertTriangle size={48} className="text-amber-500/30 mx-auto mb-4" />
                <div className="text-xs uppercase tracking-widest text-amber-500/60 mb-1">NO ASSETS DISCOVERED</div>
                <div className="text-[10px] text-gray-700 max-w-xs">This scan completed but found no assets. Try scanning a different domain.</div>
              </div>
            </div>
          )}

          {/* Engine Error */}
          {engineError && (
            <div className="absolute inset-0 z-40 flex items-center justify-center bg-[#0A0E14]">
              <div className="text-center font-mono">
                <AlertTriangle size={48} className="text-red-500 mx-auto mb-4" />
                <div className="text-xs uppercase tracking-widest text-red-400 mb-2">ENGINE INITIALIZATION FAILED</div>
                <div className="text-[10px] text-gray-500 max-w-md">{engineError}</div>
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-4 rounded-none border-[#1A2332] text-xs uppercase tracking-wider"
                  onClick={() => { setEngineError(null); window.location.reload(); }}
                >
                  RETRY
                </Button>
              </div>
            </div>
          )}

          {/* Canvas 2D Engine */}
          <div ref={containerRef} className="absolute inset-0" />

          {/* Overlays */}
          <StatsHUD stats={stats} mode={mode} />
          <ReasoningStatusBar
            reasoning={graphQuery.data?.reasoning}
            performance={graphQuery.data?.performance}
          />
          <LegendPanel visible={showLegend} />

          {/* Network Topology Filters */}
          {showTopologyFilters && (
            <div className="absolute top-2 left-2 z-40 bg-[#0A0E14]/95 border border-[#1A2332] p-3 font-mono" style={{ minWidth: 200 }}>
              <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-2 flex items-center gap-1">
                <Network size={10} />
                TOPOLOGY LAYERS
              </div>
              {[
                { key: "proxy", label: "Proxies / CDN / LB", icon: "\u{1F6E1}", color: "#FF9800" },
                { key: "gateway", label: "Network Hops", icon: "\u{1F310}", color: "#78909C" },
                { key: "c2_server", label: "C2 Infrastructure", icon: "\u{1F4E1}", color: "#FF1744" },
                { key: "tap_point", label: "Blue Team / Taps", icon: "\u{1F441}", color: "#2196F3" },
              ].map(({ key, label, icon, color }) => (
                <button
                  key={key}
                  className="flex items-center gap-2 w-full py-1 px-1 hover:bg-[#1A2332]/50 transition-colors"
                  onClick={() => {
                    const newState = { ...topologyLayers, [key]: !topologyLayers[key] };
                    setTopologyLayers(newState);
                    engineRef.current?.setNodeTypeVisibility(key, newState[key]);
                  }}
                >
                  <div
                    className="w-3 h-3 border flex items-center justify-center text-[8px]"
                    style={{
                      borderColor: color,
                      backgroundColor: topologyLayers[key] ? color + "33" : "transparent",
                    }}
                  >
                    {topologyLayers[key] && <span style={{ color }}>\u2713</span>}
                  </div>
                  <span className="text-[10px]" style={{ color: topologyLayers[key] ? color : "#555" }}>
                    {icon} {label}
                  </span>
                  {!topologyLayers[key] && (
                    <span className="text-[8px] text-gray-600 ml-auto">HIDDEN</span>
                  )}
                </button>
              ))}
              <div className="mt-2 pt-2 border-t border-[#1A2332]">
                <button
                  className="text-[9px] uppercase tracking-wider text-gray-500 hover:text-teal-400 transition-colors"
                  onClick={() => {
                    const allVisible = Object.values(topologyLayers).every(v => v);
                    const newState = Object.fromEntries(
                      Object.keys(topologyLayers).map(k => [k, !allVisible])
                    );
                    setTopologyLayers(newState);
                    Object.entries(newState).forEach(([k, v]) => {
                      engineRef.current?.setNodeTypeVisibility(k, v);
                    });
                  }}
                >
                  {Object.values(topologyLayers).every(v => v) ? "HIDE ALL" : "SHOW ALL"}
                </button>
              </div>
            </div>
          )}
          <NodeDetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} />
          <PathSelector
            paths={reasoningMerged && reasoningQuery.data?.paths ? reasoningQuery.data.paths : (graphQuery.data?.paths || [])}
            selectedPath={selectedPath}
            onSelect={setSelectedPath}
          />

          {/* Hover Tooltip */}
          {hoveredNode && (
            <div
              className="absolute z-50 bg-[#0A0E14] border border-[#1A2332] px-2 py-1 font-mono text-[9px] pointer-events-none"
              style={{ left: hoveredNode.x + 12, top: hoveredNode.y - 8 }}
            >
              <span className="text-gray-500 uppercase">{hoveredNode.node.type.replace("_", " ")}</span>
              <span className="text-gray-600 mx-1">|</span>
              <span className="text-white">{hoveredNode.node.label}</span>
              {hoveredNode.node.severity && (
                <>
                  <span className="text-gray-600 mx-1">|</span>
                  <span style={{ color: SEVERITY_COLORS[hoveredNode.node.severity] }} className="uppercase">{hoveredNode.node.severity}</span>
                </>
              )}
            </div>
          )}

          {/* Timeline Scrubber */}
          {timeRange && mode === "engagement" && (
            <TimelineScrubber
              minTime={timeRange.min}
              maxTime={timeRange.max}
              onTimeChange={handleTimeChange}
              visibleNodeCount={visibleNodeCount}
              totalNodeCount={totalNodeCount}
            />
          )}

          {/* Scan line animation (decorative) */}
          <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-teal-400/20 to-transparent animate-pulse pointer-events-none" />
          <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-teal-400/10 to-transparent pointer-events-none" />
        </div>
      </div>
  );
}
