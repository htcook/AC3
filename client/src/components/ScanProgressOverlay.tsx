import { useState, useMemo } from "react";
import {
  Radio, Shield, AlertTriangle, Activity, Target, Cpu, Globe, Server,
  ChevronUp, ChevronDown, Zap, Eye, Lock, Crosshair, Layers, Radar,
} from "lucide-react";

// ── Phase pipeline definition ─────────────────────────────────────
const PIPELINE_PHASES = [
  { key: "recon",              label: "RECON",       icon: Globe,      short: "RCN" },
  { key: "passive_discovery",  label: "PASSIVE",     icon: Eye,        short: "PSV" },
  { key: "scoping",            label: "SCOPE",       icon: Target,     short: "SCP" },
  { key: "test_plan",          label: "PLAN",        icon: Layers,     short: "PLN" },
  { key: "enumeration",        label: "ENUM",        icon: Server,     short: "ENM" },
  { key: "scanning",           label: "SCAN",        icon: Radar,      short: "SCN" },
  { key: "vuln_detection",     label: "VULN",        icon: Shield,     short: "VLN" },
  { key: "exploitation",       label: "EXPLOIT",     icon: Crosshair,  short: "EXP" },
  { key: "completed",          label: "DONE",        icon: Lock,       short: "FIN" },
] as const;

type PhaseStatus = "done" | "active" | "pending" | "error";

function getPhaseStatuses(currentPhase: string | undefined, isRunning: boolean, hasError: boolean): Record<string, PhaseStatus> {
  const statuses: Record<string, PhaseStatus> = {};
  let found = false;

  for (const p of PIPELINE_PHASES) {
    if (p.key === currentPhase) {
      found = true;
      statuses[p.key] = hasError ? "error" : isRunning ? "active" : "done";
    } else if (!found) {
      statuses[p.key] = "done";
    } else {
      statuses[p.key] = "pending";
    }
  }

  // If phase not found in list, mark everything as pending
  if (!found && currentPhase) {
    for (const p of PIPELINE_PHASES) {
      statuses[p.key] = "pending";
    }
  }

  return statuses;
}

const STATUS_COLORS: Record<PhaseStatus, { bg: string; border: string; text: string; dot: string }> = {
  done:    { bg: "bg-teal-500/10", border: "border-teal-500/30", text: "text-teal-400",  dot: "bg-teal-400" },
  active:  { bg: "bg-amber-500/10", border: "border-amber-500/30", text: "text-amber-400", dot: "bg-amber-400" },
  pending: { bg: "bg-gray-500/5",  border: "border-[#1A2332]",    text: "text-gray-600",  dot: "bg-gray-600" },
  error:   { bg: "bg-red-500/10",  border: "border-red-500/30",   text: "text-red-400",   dot: "bg-red-400" },
};

// ── Log entry component ───────────────────────────────────────────
function LogEntry({ entry, index }: { entry: any; index: number }) {
  const typeColors: Record<string, string> = {
    info: "text-gray-400",
    success: "text-teal-400",
    warning: "text-amber-400",
    error: "text-red-400",
    phase_start: "text-cyan-400",
    phase_complete: "text-teal-400",
    tool_start: "text-blue-400",
    tool_complete: "text-blue-300",
  };

  const typeIcons: Record<string, string> = {
    info: "ℹ",
    success: "✓",
    warning: "⚠",
    error: "✗",
    phase_start: "▶",
    phase_complete: "■",
    tool_start: "⚙",
    tool_complete: "✓",
  };

  const color = typeColors[entry.type] || "text-gray-500";
  const icon = typeIcons[entry.type] || "·";

  return (
    <div className="flex items-start gap-2 py-0.5 group" style={{ opacity: 1 - index * 0.15 }}>
      <span className={`${color} text-[9px] w-3 flex-shrink-0 text-center`}>{icon}</span>
      <span className="text-[9px] text-gray-600 flex-shrink-0 w-12">
        {entry.phase ? `[${entry.phase.slice(0, 5).toUpperCase()}]` : ""}
      </span>
      <span className={`text-[9px] ${color} truncate`} title={entry.title || entry.detail}>
        {entry.title || entry.detail || "Processing..."}
      </span>
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────
interface ScanProgressOverlayProps {
  opsState: any;
  /** "full" = centered overlay when no graph data, "bar" = bottom bar when graph has data */
  variant: "full" | "bar";
}

export function ScanProgressOverlay({ opsState, variant }: ScanProgressOverlayProps) {
  const [expanded, setExpanded] = useState(true);

  const phase = opsState?.phase || "initializing";
  const isRunning = opsState?.isRunning ?? false;
  const hasError = !!opsState?.error;
  const stats = opsState?.stats || {};
  const assets = opsState?.assets || [];
  const log = (opsState?.log || []) as any[];

  const phaseStatuses = useMemo(
    () => getPhaseStatuses(phase, isRunning, hasError),
    [phase, isRunning, hasError]
  );

  // Derive active tools from recent log entries
  const activeTools = useMemo(() => {
    const tools = new Set<string>();
    const recentLogs = log.slice(-20);
    for (const entry of recentLogs) {
      const title = (entry.title || "").toLowerCase();
      if (title.includes("nuclei")) tools.add("Nuclei");
      if (title.includes("zap")) tools.add("ZAP");
      if (title.includes("burp")) tools.add("Burp");
      if (title.includes("katana")) tools.add("Katana");
      if (title.includes("feroxbuster")) tools.add("Feroxbuster");
      if (title.includes("ffuf")) tools.add("ffuf");
      if (title.includes("arjun")) tools.add("Arjun");
      if (title.includes("testssl")) tools.add("testssl");
      if (title.includes("wafw00f")) tools.add("wafw00f");
      if (title.includes("nikto")) tools.add("Nikto");
      if (title.includes("gobuster")) tools.add("Gobuster");
      if (title.includes("hydra")) tools.add("Hydra");
      if (title.includes("scanforge") || title.includes("scan forge")) tools.add("ScanForge");
      if (title.includes("naabu")) tools.add("Naabu");
      if (title.includes("subfinder")) tools.add("Subfinder");
      if (title.includes("httpx")) tools.add("httpx");
    }
    return Array.from(tools);
  }, [log]);

  const totalPorts = assets.reduce((s: number, a: any) => s + (a.ports?.length || 0), 0);
  const totalVulns = stats.vulnsFound ?? assets.reduce((s: number, a: any) => s + (a.vulns?.length || 0), 0);

  // ── FULL OVERLAY (centered, when no graph data) ──
  if (variant === "full") {
    return (
      <div className="absolute inset-0 z-30 flex items-center justify-center">
        <div className="text-center font-mono max-w-lg w-full px-4">
          {/* Animated radar icon */}
          <div className="relative mx-auto mb-6 w-20 h-20">
            <div className="absolute inset-0 border-2 border-teal-500/20 rounded-full" />
            <div className="absolute inset-2 border border-teal-500/10 rounded-full" />
            <div className="absolute inset-0 border-2 border-transparent border-t-teal-400 rounded-full animate-spin" style={{ animationDuration: "2s" }} />
            <Radio size={28} className="absolute inset-0 m-auto text-teal-400 animate-pulse" />
          </div>

          <div className="text-sm uppercase tracking-[0.3em] text-teal-400 mb-1">SCAN IN PROGRESS</div>
          <div className="text-[10px] text-gray-500 mb-6">
            Phase: <span className="text-gray-300">{phase.replace(/_/g, " ").toUpperCase()}</span>
          </div>

          {/* Phase pipeline */}
          <div className="flex items-center justify-center gap-0.5 mb-6">
            {PIPELINE_PHASES.map((p, i) => {
              const status = phaseStatuses[p.key] || "pending";
              const colors = STATUS_COLORS[status];
              const Icon = p.icon;
              return (
                <div key={p.key} className="flex items-center">
                  <div
                    className={`${colors.bg} ${colors.border} border px-1.5 py-1 flex flex-col items-center gap-0.5 relative`}
                    title={p.label}
                  >
                    <Icon size={10} className={colors.text} />
                    <span className={`text-[7px] ${colors.text} tracking-wider`}>{p.short}</span>
                    {status === "active" && (
                      <div className={`absolute -top-0.5 -right-0.5 w-1.5 h-1.5 ${colors.dot} rounded-full animate-pulse`} />
                    )}
                  </div>
                  {i < PIPELINE_PHASES.length - 1 && (
                    <div className={`w-2 h-px ${status === "done" ? "bg-teal-500/40" : "bg-[#1A2332]"}`} />
                  )}
                </div>
              );
            })}
          </div>

          {/* Stats grid */}
          <div className="grid grid-cols-4 gap-2 mb-5">
            <StatCell label="HOSTS" value={stats.hostsScanned ?? 0} color="text-white" />
            <StatCell label="PORTS" value={totalPorts} color="text-cyan-400" />
            <StatCell label="VULNS" value={totalVulns} color="text-amber-400" />
            <StatCell label="ASSETS" value={stats.assetsDiscovered ?? assets.length ?? 0} color="text-teal-400" />
            <StatCell label="ZAP SCANS" value={stats.zapScansRun ?? 0} color="text-purple-400" />
            <StatCell label="WAF HITS" value={stats.wafDetections ?? 0} color="text-orange-400" />
            <StatCell label="EXPLOITS" value={stats.exploitsAttempted ?? 0} color="text-red-400" />
            <StatCell label="SHELLS" value={stats.sessionsOpened ?? 0} color="text-green-400" />
          </div>

          {/* Active tools */}
          {activeTools.length > 0 && (
            <div className="mb-4">
              <div className="text-[8px] uppercase tracking-widest text-gray-600 mb-1.5">ACTIVE TOOLS</div>
              <div className="flex flex-wrap justify-center gap-1">
                {activeTools.map(tool => (
                  <span key={tool} className="bg-[#111820] border border-[#1A2332] px-2 py-0.5 text-[8px] text-teal-400 uppercase tracking-wider">
                    <Cpu size={7} className="inline mr-1" />{tool}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Log feed */}
          {log.length > 0 && (
            <div className="bg-[#0A0E14] border border-[#1A2332] p-2 text-left max-w-md mx-auto">
              <div className="text-[8px] uppercase tracking-widest text-gray-600 mb-1">LIVE LOG</div>
              {log.slice(-5).reverse().map((entry: any, i: number) => (
                <LogEntry key={i} entry={entry} index={i} />
              ))}
            </div>
          )}

          <div className="text-[9px] text-gray-600 mt-4">Graph will render automatically when findings are available.</div>
        </div>
      </div>
    );
  }

  // ── BAR VARIANT (bottom bar, when graph has data) ──
  if (!isRunning) return null;

  return (
    <div className="absolute bottom-0 left-0 right-0 z-30 font-mono">
      {/* Expand/collapse toggle */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="absolute -top-6 left-1/2 -translate-x-1/2 bg-[#0A0E14] border border-[#1A2332] border-b-0 px-3 py-0.5 flex items-center gap-1.5 text-[8px] text-teal-400 uppercase tracking-widest hover:text-teal-300 transition-colors"
      >
        <Radio size={8} className="animate-pulse" />
        SCAN ACTIVE
        {expanded ? <ChevronDown size={8} /> : <ChevronUp size={8} />}
      </button>

      {expanded && (
        <div className="bg-[#0A0E14]/95 backdrop-blur-sm border-t border-[#1A2332] p-2">
          <div className="flex items-center gap-4">
            {/* Phase pipeline (compact) */}
            <div className="flex items-center gap-px flex-shrink-0">
              {PIPELINE_PHASES.map((p, i) => {
                const status = phaseStatuses[p.key] || "pending";
                const colors = STATUS_COLORS[status];
                return (
                  <div key={p.key} className="flex items-center">
                    <div
                      className={`w-2 h-2 ${colors.dot} ${status === "active" ? "animate-pulse" : ""}`}
                      title={`${p.label}: ${status}`}
                    />
                    {i < PIPELINE_PHASES.length - 1 && (
                      <div className={`w-1 h-px ${status === "done" ? "bg-teal-500/40" : "bg-[#1A2332]"}`} />
                    )}
                  </div>
                );
              })}
            </div>

            {/* Current phase label */}
            <div className="text-[9px] text-gray-400 flex-shrink-0">
              <span className="text-teal-400">{phase.replace(/_/g, " ").toUpperCase()}</span>
            </div>

            {/* Compact stats */}
            <div className="flex items-center gap-3 text-[9px] flex-shrink-0">
              <span className="text-gray-500">
                <span className="text-cyan-400">{totalPorts}</span> ports
              </span>
              <span className="text-gray-500">
                <span className="text-amber-400">{totalVulns}</span> vulns
              </span>
              <span className="text-gray-500">
                <span className="text-red-400">{stats.exploitsAttempted ?? 0}</span> exploits
              </span>
              {stats.zapScansRun > 0 && (
                <span className="text-gray-500">
                  <span className="text-purple-400">{stats.zapScansRun}</span> ZAP
                </span>
              )}
            </div>

            {/* Active tools (compact) */}
            {activeTools.length > 0 && (
              <div className="flex items-center gap-1 flex-shrink-0">
                <Cpu size={8} className="text-gray-600" />
                {activeTools.slice(0, 4).map(tool => (
                  <span key={tool} className="text-[8px] text-teal-400/70">{tool}</span>
                ))}
                {activeTools.length > 4 && (
                  <span className="text-[8px] text-gray-600">+{activeTools.length - 4}</span>
                )}
              </div>
            )}

            {/* Latest log (fills remaining space) */}
            <div className="flex-1 min-w-0 text-[9px] text-gray-500 truncate" title={log[log.length - 1]?.title}>
              {log[log.length - 1]?.title || "Processing..."}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Stat cell helper ──────────────────────────────────────────────
function StatCell({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-[#111820] border border-[#1A2332] p-2 text-center">
      <div className={`text-lg font-bold ${color}`}>{value}</div>
      <div className="text-[7px] uppercase tracking-widest text-gray-600">{label}</div>
    </div>
  );
}
