/**
 * VisualEffectToggles — Ops Viewer rendering controls
 * ════════════════════════════════════════════════════
 * Dropdown panel of toggle switches for visual effects.
 * Persists preferences to localStorage.
 */
import { useState, useEffect, useCallback } from "react";
import type { EngineOptions } from "@/lib/battlespace-engine";
import {
  Sparkles, Grid3X3, Eye, Flame, Activity, Radar, MonitorDot,
  Layers, ChevronDown,
} from "lucide-react";

interface VisualEffectTogglesProps {
  /** Current engine options */
  options: Partial<EngineOptions>;
  /** Called when a toggle changes */
  onToggle: (key: keyof EngineOptions, value: boolean) => void;
}

const STORAGE_KEY = "ops-viewer-visual-prefs";

interface ToggleDef {
  key: keyof EngineOptions;
  label: string;
  description: string;
  icon: React.ReactNode;
  color: string;
}

const TOGGLES: ToggleDef[] = [
  {
    key: "edgeBloomEnabled",
    label: "EDGE BLOOM",
    description: "Multi-pass glow rendering on edges",
    icon: <Sparkles size={10} />,
    color: "#00E5CC",
  },
  {
    key: "nodeHeartbeatEnabled",
    label: "HEARTBEAT",
    description: "Pulse rings on active agents/C2 nodes",
    icon: <Activity size={10} />,
    color: "#FF0040",
  },
  {
    key: "heatmapEnabled",
    label: "THREAT HEATMAP",
    description: "Radial gradients behind critical clusters",
    icon: <Flame size={10} />,
    color: "#FF6B00",
  },
  {
    key: "hudEnabled",
    label: "HUD OVERLAY",
    description: "Military C2-style stats display",
    icon: <MonitorDot size={10} />,
    color: "#00E5CC",
  },
  {
    key: "particlesEnabled",
    label: "PARTICLES",
    description: "Animated data flow particles on edges",
    icon: <Radar size={10} />,
    color: "#FFB800",
  },
  {
    key: "glowEnabled",
    label: "NODE GLOW",
    description: "Glow effects on critical/high severity nodes",
    icon: <Eye size={10} />,
    color: "#FF0040",
  },
  {
    key: "gridEnabled",
    label: "GRID",
    description: "Background coordinate grid",
    icon: <Grid3X3 size={10} />,
    color: "#1A2332",
  },
  {
    key: "animatedPathReveal",
    label: "PATH ANIMATION",
    description: "Sequential edge lighting on path selection",
    icon: <Layers size={10} />,
    color: "#FFB800",
  },
];

export function VisualEffectToggles({ options, onToggle }: VisualEffectTogglesProps) {
  const [isOpen, setIsOpen] = useState(false);

  // Load saved preferences on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const prefs = JSON.parse(saved) as Record<string, boolean>;
        for (const toggle of TOGGLES) {
          if (toggle.key in prefs) {
            onToggle(toggle.key, prefs[toggle.key]);
          }
        }
      }
    } catch {
      // ignore parse errors
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleToggle = useCallback(
    (key: keyof EngineOptions) => {
      const current = options[key] as boolean;
      const next = !current;
      onToggle(key, next);

      // Persist to localStorage
      try {
        const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
        saved[key] = next;
        localStorage.setItem(STORAGE_KEY, JSON.stringify(saved));
      } catch {
        // ignore
      }
    },
    [options, onToggle]
  );

  const enabledCount = TOGGLES.filter((t) => options[t.key] as boolean).length;

  return (
    <div className="relative">
      {/* Trigger button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`h-7 px-2 flex items-center gap-1 border rounded-none text-[10px] uppercase tracking-wider font-mono transition-colors ${
          isOpen
            ? "bg-[#1A2332] border-teal-400/30 text-teal-400"
            : "bg-transparent border-[#1A2332] text-gray-400 hover:text-white hover:border-gray-600"
        }`}
        title="Visual Effect Toggles"
      >
        <Sparkles size={10} />
        <span>FX</span>
        <span className="text-[8px] text-teal-400">{enabledCount}/{TOGGLES.length}</span>
        <ChevronDown size={8} className={`transition-transform ${isOpen ? "rotate-180" : ""}`} />
      </button>

      {/* Dropdown panel */}
      {isOpen && (
        <>
          {/* Backdrop */}
          <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />

          {/* Panel */}
          <div className="absolute right-0 top-full mt-1 z-50 bg-[#0A0E14]/98 border border-[#1A2332] backdrop-blur-sm min-w-[260px] shadow-xl shadow-black/50">
            {/* Header */}
            <div className="px-3 py-2 border-b border-[#1A2332] flex items-center justify-between">
              <div className="font-mono text-[9px] uppercase tracking-widest text-gray-500 flex items-center gap-1.5">
                <Sparkles size={9} className="text-teal-400" />
                VISUAL EFFECTS
              </div>
              <div className="flex gap-1">
                <button
                  onClick={() => {
                    TOGGLES.forEach((t) => onToggle(t.key, true));
                    const all: Record<string, boolean> = {};
                    TOGGLES.forEach((t) => (all[t.key] = true));
                    localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
                  }}
                  className="font-mono text-[8px] uppercase tracking-wider text-gray-600 hover:text-teal-400 transition-colors px-1"
                >
                  ALL ON
                </button>
                <span className="text-gray-700">|</span>
                <button
                  onClick={() => {
                    TOGGLES.forEach((t) => onToggle(t.key, false));
                    const all: Record<string, boolean> = {};
                    TOGGLES.forEach((t) => (all[t.key] = false));
                    localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
                  }}
                  className="font-mono text-[8px] uppercase tracking-wider text-gray-600 hover:text-red-400 transition-colors px-1"
                >
                  ALL OFF
                </button>
              </div>
            </div>

            {/* Toggle list */}
            <div className="py-1">
              {TOGGLES.map((toggle) => {
                const isEnabled = options[toggle.key] as boolean;
                return (
                  <button
                    key={toggle.key}
                    onClick={() => handleToggle(toggle.key)}
                    className="w-full flex items-center gap-3 px-3 py-1.5 hover:bg-[#1A2332]/50 transition-colors group"
                  >
                    {/* Toggle indicator */}
                    <div
                      className="w-7 h-3.5 rounded-full relative transition-colors flex-shrink-0"
                      style={{
                        backgroundColor: isEnabled ? toggle.color + "33" : "#111820",
                        border: `1px solid ${isEnabled ? toggle.color : "#1A2332"}`,
                      }}
                    >
                      <div
                        className="absolute top-0.5 w-2 h-2 rounded-full transition-all"
                        style={{
                          left: isEnabled ? "calc(100% - 10px)" : "2px",
                          backgroundColor: isEnabled ? toggle.color : "#333",
                          boxShadow: isEnabled ? `0 0 4px ${toggle.color}` : "none",
                        }}
                      />
                    </div>

                    {/* Icon */}
                    <span style={{ color: isEnabled ? toggle.color : "#555" }}>
                      {toggle.icon}
                    </span>

                    {/* Label + description */}
                    <div className="flex-1 text-left">
                      <div
                        className="font-mono text-[9px] uppercase tracking-wider"
                        style={{ color: isEnabled ? "#ddd" : "#555" }}
                      >
                        {toggle.label}
                      </div>
                      <div className="font-mono text-[7px] text-gray-600 group-hover:text-gray-500 transition-colors">
                        {toggle.description}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Performance hint */}
            <div className="px-3 py-1.5 border-t border-[#1A2332]">
              <div className="font-mono text-[7px] text-gray-600">
                Disable effects for better performance on large graphs. Preferences are saved locally.
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
