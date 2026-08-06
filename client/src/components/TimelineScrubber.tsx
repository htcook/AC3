/**
 * TimelineScrubber — Chronological engagement replay control
 * ═══════════════════════════════════════════════════════════
 * Renders a horizontal timeline bar at the bottom of the Ops Viewer.
 * Operators can scrub through time to replay how the attack surface
 * was discovered, or hit Play to watch it unfold automatically.
 */
import { useState, useRef, useCallback, useEffect, useMemo } from "react";
import { Play, Pause, SkipBack, SkipForward, Clock, FastForward } from "lucide-react";
import { Button } from "@/components/ui/button";

interface TimelineScrubberProps {
  /** Min timestamp (ms) across all nodes */
  minTime: number;
  /** Max timestamp (ms) across all nodes */
  maxTime: number;
  /** Called when the user scrubs or playback advances */
  onTimeChange: (startMs: number | null, endMs: number | null) => void;
  /** Number of nodes currently visible */
  visibleNodeCount?: number;
  /** Total number of nodes */
  totalNodeCount?: number;
}

const SPEED_OPTIONS = [0.5, 1, 2, 4, 8] as const;

export function TimelineScrubber({
  minTime,
  maxTime,
  onTimeChange,
  visibleNodeCount,
  totalNodeCount,
}: TimelineScrubberProps) {
  const [currentTime, setCurrentTime] = useState(maxTime);
  const [isPlaying, setIsPlaying] = useState(false);
  const [speedIdx, setSpeedIdx] = useState(1); // default 1x
  const [isExpanded, setIsExpanded] = useState(true);
  const animRef = useRef<number | null>(null);
  const lastFrameRef = useRef<number>(0);

  const speed = SPEED_OPTIONS[speedIdx];
  const duration = maxTime - minTime;
  const progress = duration > 0 ? (currentTime - minTime) / duration : 1;

  // Reset when time range changes (new engagement loaded)
  useEffect(() => {
    setCurrentTime(maxTime);
    setIsPlaying(false);
    onTimeChange(null, null); // show all
  }, [minTime, maxTime]);

  // Playback loop
  useEffect(() => {
    if (!isPlaying) {
      if (animRef.current) cancelAnimationFrame(animRef.current);
      return;
    }

    lastFrameRef.current = performance.now();

    const tick = (now: number) => {
      const dt = now - lastFrameRef.current;
      lastFrameRef.current = now;

      // Advance time: 1x speed = real-time duration plays in 30 seconds
      const timePerMs = (duration / 30000) * speed;
      const newTime = Math.min(currentTime + dt * timePerMs, maxTime);

      setCurrentTime(newTime);
      onTimeChange(minTime, newTime);

      if (newTime >= maxTime) {
        setIsPlaying(false);
        onTimeChange(null, null); // show all at end
        return;
      }

      animRef.current = requestAnimationFrame(tick);
    };

    animRef.current = requestAnimationFrame(tick);
    return () => {
      if (animRef.current) cancelAnimationFrame(animRef.current);
    };
  }, [isPlaying, currentTime, speed, minTime, maxTime, duration, onTimeChange]);

  const handleScrub = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      const rect = e.currentTarget.getBoundingClientRect();
      const pct = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      const newTime = minTime + pct * duration;
      setCurrentTime(newTime);
      onTimeChange(minTime, newTime);
    },
    [minTime, duration, onTimeChange]
  );

  const handleDrag = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (e.buttons !== 1) return;
      handleScrub(e);
    },
    [handleScrub]
  );

  const resetToStart = useCallback(() => {
    setCurrentTime(minTime);
    setIsPlaying(false);
    onTimeChange(minTime, minTime);
  }, [minTime, onTimeChange]);

  const jumpToEnd = useCallback(() => {
    setCurrentTime(maxTime);
    setIsPlaying(false);
    onTimeChange(null, null); // show all
  }, [maxTime, onTimeChange]);

  const togglePlay = useCallback(() => {
    if (!isPlaying && currentTime >= maxTime) {
      // If at end, restart from beginning
      setCurrentTime(minTime);
      onTimeChange(minTime, minTime);
    }
    setIsPlaying((p) => !p);
  }, [isPlaying, currentTime, maxTime, minTime, onTimeChange]);

  const cycleSpeed = useCallback(() => {
    setSpeedIdx((i) => (i + 1) % SPEED_OPTIONS.length);
  }, []);

  const formatTime = (ms: number) => {
    const d = new Date(ms);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  };

  const formatDuration = (ms: number) => {
    const totalSec = Math.floor(ms / 1000);
    const days = Math.floor(totalSec / 86400);
    const hours = Math.floor((totalSec % 86400) / 3600);
    const mins = Math.floor((totalSec % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
  };

  if (!isExpanded) {
    return (
      <button
        onClick={() => setIsExpanded(true)}
        className="absolute bottom-3 left-1/2 -translate-x-1/2 z-20 bg-[#0A0E14]/95 border border-[#1A2332] px-3 py-1.5 font-mono text-[9px] uppercase tracking-widest text-gray-400 hover:text-teal-400 hover:border-teal-400/30 transition-colors flex items-center gap-2"
      >
        <Clock size={10} />
        TIMELINE
      </button>
    );
  }

  return (
    <div className="absolute bottom-0 left-0 right-0 z-20 bg-[#0A0E14]/95 border-t border-[#1A2332] backdrop-blur-sm">
      {/* Main scrub bar */}
      <div
        className="h-6 relative cursor-pointer group"
        onClick={handleScrub}
        onMouseMove={handleDrag}
      >
        {/* Background track */}
        <div className="absolute inset-0 bg-[#111820]" />

        {/* Progress fill */}
        <div
          className="absolute top-0 left-0 bottom-0 transition-[width] duration-75"
          style={{
            width: `${progress * 100}%`,
            background: "linear-gradient(90deg, rgba(0,229,204,0.15) 0%, rgba(0,229,204,0.3) 100%)",
          }}
        />

        {/* Tick marks — show 10 evenly spaced markers */}
        {Array.from({ length: 11 }, (_, i) => (
          <div
            key={i}
            className="absolute top-0 bottom-0 w-px bg-[#1A2332]"
            style={{ left: `${(i / 10) * 100}%` }}
          />
        ))}

        {/* Playhead */}
        <div
          className="absolute top-0 bottom-0 w-0.5 bg-teal-400 shadow-[0_0_6px_rgba(0,229,204,0.5)]"
          style={{ left: `${progress * 100}%` }}
        >
          <div className="absolute -top-0 left-1/2 -translate-x-1/2 w-2 h-2 bg-teal-400 rotate-45" />
        </div>

        {/* Hover timestamp tooltip */}
        <div className="absolute top-0 left-0 right-0 bottom-0 opacity-0 group-hover:opacity-100 pointer-events-none">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-[#0A0E14] border border-teal-400/30 px-2 py-0.5 font-mono text-[8px] text-teal-400 whitespace-nowrap">
            {formatTime(currentTime)}
          </div>
        </div>
      </div>

      {/* Controls bar */}
      <div className="flex items-center gap-2 px-3 py-1.5">
        {/* Transport controls */}
        <Button
          variant="outline"
          size="sm"
          className="h-6 w-6 p-0 rounded-none border-[#1A2332] bg-transparent hover:bg-[#1A2332]"
          onClick={resetToStart}
          title="Jump to Start"
        >
          <SkipBack size={10} />
        </Button>

        <Button
          variant="outline"
          size="sm"
          className={`h-6 w-6 p-0 rounded-none border-[#1A2332] ${isPlaying ? "bg-teal-400/20 text-teal-400 border-teal-400/30" : "bg-transparent"}`}
          onClick={togglePlay}
          title={isPlaying ? "Pause" : "Play"}
        >
          {isPlaying ? <Pause size={10} /> : <Play size={10} />}
        </Button>

        <Button
          variant="outline"
          size="sm"
          className="h-6 w-6 p-0 rounded-none border-[#1A2332] bg-transparent hover:bg-[#1A2332]"
          onClick={jumpToEnd}
          title="Jump to End (Show All)"
        >
          <SkipForward size={10} />
        </Button>

        {/* Speed control */}
        <button
          onClick={cycleSpeed}
          className="h-6 px-2 border border-[#1A2332] bg-transparent hover:bg-[#1A2332] font-mono text-[9px] uppercase tracking-wider text-gray-400 hover:text-teal-400 transition-colors flex items-center gap-1"
          title="Playback Speed"
        >
          <FastForward size={8} />
          {speed}x
        </button>

        <div className="h-4 w-px bg-[#1A2332]" />

        {/* Time display */}
        <div className="font-mono text-[9px] uppercase tracking-wider text-gray-500 flex items-center gap-2">
          <Clock size={9} className="text-teal-400" />
          <span className="text-teal-400">{formatTime(currentTime)}</span>
          <span className="text-gray-700">|</span>
          <span>{formatTime(minTime)}</span>
          <span className="text-gray-700">→</span>
          <span>{formatTime(maxTime)}</span>
          <span className="text-gray-700">|</span>
          <span>SPAN: {formatDuration(duration)}</span>
        </div>

        <div className="flex-1" />

        {/* Node count indicator */}
        {visibleNodeCount != null && totalNodeCount != null && (
          <div className="font-mono text-[9px] uppercase tracking-wider text-gray-500 flex items-center gap-1">
            <span className="text-teal-400">{visibleNodeCount}</span>
            <span>/</span>
            <span>{totalNodeCount}</span>
            <span>NODES</span>
          </div>
        )}

        <div className="h-4 w-px bg-[#1A2332]" />

        {/* Collapse button */}
        <button
          onClick={() => setIsExpanded(false)}
          className="font-mono text-[8px] uppercase tracking-wider text-gray-600 hover:text-gray-400 transition-colors"
        >
          HIDE
        </button>
      </div>
    </div>
  );
}
