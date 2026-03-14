/**
 * EngagementTerminal — Unified CLI terminal for pentesting
 *
 * Two modes:
 * 1. Manual CLI: Pentester runs commands against in-scope assets
 * 2. Exploit Shell: Opens automatically when an exploit pops a shell
 *
 * All command output is captured as evidence and fed back into engagement findings.
 */
import { useState, useRef, useEffect, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Terminal, X, Maximize2, Minimize2, Loader2, ChevronUp, ChevronDown,
  AlertTriangle, Shield, Send, Trash2, Download, Copy, Check,
} from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TooltipProvider,
} from "@/components/ui/tooltip";

export interface TerminalEntry {
  id: string;
  command: string;
  output: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  timestamp: string;
  isRunning?: boolean;
}

interface EngagementTerminalProps {
  engagementId: number;
  /** In-scope assets for this engagement */
  assets: Array<{ hostname: string; ip?: string; ports?: number[] }>;
  /** Pre-fill context when exploit pops a shell */
  exploitContext?: {
    shellType: string;
    targetHost: string;
    targetPort?: number;
    shellPayload?: string;
    stabilizationCmds?: string[];
    exploitName?: string;
  };
  /** Whether the terminal is open */
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const SUGGESTED_COMMANDS = [
  { label: "System Info", cmd: "whoami && id && hostname && uname -a" },
  { label: "Network", cmd: "ifconfig 2>/dev/null || ip addr" },
  { label: "Users", cmd: "cat /etc/passwd | grep -v nologin | grep -v false" },
  { label: "Processes", cmd: "ps aux --sort=-%mem | head -20" },
  { label: "Connections", cmd: "netstat -tulnp 2>/dev/null || ss -tulnp" },
  { label: "Crontabs", cmd: "crontab -l 2>/dev/null; ls -la /etc/cron*" },
  { label: "SUID Binaries", cmd: "find / -perm -4000 -type f 2>/dev/null | head -20" },
  { label: "Writable Dirs", cmd: "find / -writable -type d 2>/dev/null | head -20" },
  { label: "SSH Keys", cmd: "find / -name authorized_keys -o -name id_rsa 2>/dev/null" },
  { label: "Env Vars", cmd: "env | sort" },
];

const NMAP_SUGGESTIONS = [
  { label: "Quick Scan", cmd: (h: string) => `nmap -sV -sC -T4 ${h}` },
  { label: "Full Port Scan", cmd: (h: string) => `nmap -p- -T4 ${h}` },
  { label: "Vuln Scan", cmd: (h: string) => `nmap --script vuln -T4 ${h}` },
  { label: "UDP Scan", cmd: (h: string) => `nmap -sU --top-ports 100 -T4 ${h}` },
];

export default function EngagementTerminal({
  engagementId,
  assets,
  exploitContext,
  open,
  onOpenChange,
}: EngagementTerminalProps) {
  const [entries, setEntries] = useState<TerminalEntry[]>([]);
  const [currentCmd, setCurrentCmd] = useState("");
  const [historyIdx, setHistoryIdx] = useState(-1);
  const [isMaximized, setIsMaximized] = useState(false);
  const [copied, setCopied] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState(assets[0]?.hostname || "");
  const inputRef = useRef<HTMLInputElement>(null);
  const outputRef = useRef<HTMLDivElement>(null);
  const cmdHistory = useRef<string[]>([]);

  const runCommandMut = trpc.engagementOps.runTerminalCommand.useMutation();

  // Auto-scroll to bottom on new entries
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [entries]);

  // Focus input when opened
  useEffect(() => {
    if (open && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [open]);

  // Run stabilization commands when exploit shell opens
  useEffect(() => {
    if (exploitContext?.stabilizationCmds?.length && entries.length === 0) {
      const banner: TerminalEntry = {
        id: `banner_${Date.now()}`,
        command: "",
        output: [
          `\x1b[32m[+] Shell obtained via ${exploitContext.shellType} on ${exploitContext.targetHost}${exploitContext.targetPort ? `:${exploitContext.targetPort}` : ""}`,
          exploitContext.exploitName ? `[+] Exploit: ${exploitContext.exploitName}` : "",
          `[+] Running stabilization commands...\x1b[0m`,
          "",
        ].filter(Boolean).join("\n"),
        stderr: "",
        exitCode: 0,
        durationMs: 0,
        timestamp: new Date().toISOString(),
      };
      setEntries([banner]);
      if (exploitContext.targetHost) {
        setSelectedAsset(exploitContext.targetHost);
      }
    }
  }, [exploitContext]);

  const executeCommand = useCallback(async (cmd: string) => {
    if (!cmd.trim()) return;

    cmdHistory.current.push(cmd);
    setHistoryIdx(-1);

    const entryId = `cmd_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    const runningEntry: TerminalEntry = {
      id: entryId,
      command: cmd,
      output: "",
      stderr: "",
      exitCode: -1,
      durationMs: 0,
      timestamp: new Date().toISOString(),
      isRunning: true,
    };

    setEntries((prev) => [...prev, runningEntry]);
    setCurrentCmd("");

    try {
      const result = await runCommandMut.mutateAsync({
        engagementId,
        command: cmd,
        targetHost: selectedAsset || undefined,
        timeoutSeconds: 120,
      });

      setEntries((prev) =>
        prev.map((e) =>
          e.id === entryId
            ? {
                ...e,
                output: result.stdout || "",
                stderr: result.stderr || "",
                exitCode: result.exitCode,
                durationMs: result.durationMs,
                isRunning: false,
              }
            : e
        )
      );
    } catch (err: any) {
      setEntries((prev) =>
        prev.map((e) =>
          e.id === entryId
            ? {
                ...e,
                stderr: err.message || "Command execution failed",
                exitCode: -1,
                durationMs: 0,
                isRunning: false,
              }
            : e
        )
      );
    }
  }, [engagementId, selectedAsset, runCommandMut]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      executeCommand(currentCmd);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const history = cmdHistory.current;
      if (history.length > 0) {
        const newIdx = historyIdx === -1 ? history.length - 1 : Math.max(0, historyIdx - 1);
        setHistoryIdx(newIdx);
        setCurrentCmd(history[newIdx]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const history = cmdHistory.current;
      if (historyIdx >= 0) {
        const newIdx = historyIdx + 1;
        if (newIdx >= history.length) {
          setHistoryIdx(-1);
          setCurrentCmd("");
        } else {
          setHistoryIdx(newIdx);
          setCurrentCmd(history[newIdx]);
        }
      }
    } else if (e.key === "c" && e.ctrlKey) {
      // Ctrl+C — cancel running command visual
      setCurrentCmd("");
    } else if (e.key === "l" && e.ctrlKey) {
      e.preventDefault();
      setEntries([]);
    }
  };

  const copyAllOutput = () => {
    const text = entries
      .map((e) => `$ ${e.command}\n${e.output}${e.stderr ? `\n[stderr] ${e.stderr}` : ""}`)
      .join("\n\n");
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const exportSession = () => {
    const text = entries
      .map((e) => {
        const header = `$ ${e.command}  [exit:${e.exitCode} ${e.durationMs}ms @ ${new Date(e.timestamp).toLocaleString()}]`;
        return `${header}\n${e.output}${e.stderr ? `\n[STDERR]\n${e.stderr}` : ""}`;
      })
      .join("\n" + "─".repeat(80) + "\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `terminal_session_${engagementId}_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!open) return null;

  const terminalHeight = isMaximized ? "h-[85vh]" : "h-[450px]";

  return (
    <TooltipProvider>
      <div className={`fixed bottom-0 left-0 right-0 z-50 bg-black/95 border-t border-green-500/30 ${terminalHeight} flex flex-col transition-all duration-200`}>
        {/* ── Header Bar ── */}
        <div className="flex items-center justify-between px-4 py-2 bg-zinc-900/90 border-b border-green-500/20 shrink-0">
          <div className="flex items-center gap-3">
            <Terminal className="h-4 w-4 text-green-400" />
            <span className="text-sm font-mono text-green-400 font-medium">
              {exploitContext ? "Exploit Shell" : "Pentest Terminal"}
            </span>
            {exploitContext && (
              <Badge variant="outline" className="text-[10px] text-green-400 border-green-500/30">
                {exploitContext.shellType} @ {exploitContext.targetHost}
              </Badge>
            )}
            <span className="text-[10px] text-muted-foreground">
              Engagement #{engagementId}
            </span>
          </div>

          <div className="flex items-center gap-1">
            {/* Asset selector */}
            <select
              value={selectedAsset}
              onChange={(e) => setSelectedAsset(e.target.value)}
              className="bg-zinc-800 text-green-300 text-[11px] font-mono border border-zinc-700 rounded px-2 py-1 mr-2"
            >
              <option value="">All Assets</option>
              {assets.map((a) => (
                <option key={a.hostname} value={a.hostname}>
                  {a.hostname}{a.ip ? ` (${a.ip})` : ""}
                </option>
              ))}
            </select>

            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="h-7 w-7 text-zinc-400 hover:text-green-400" onClick={copyAllOutput}>
                  {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                </Button>
              </TooltipTrigger>
              <TooltipContent>Copy all output</TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="h-7 w-7 text-zinc-400 hover:text-green-400" onClick={exportSession}>
                  <Download className="h-3.5 w-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Export session</TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="h-7 w-7 text-zinc-400 hover:text-green-400" onClick={() => setEntries([])}>
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Clear (Ctrl+L)</TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="h-7 w-7 text-zinc-400 hover:text-green-400" onClick={() => setIsMaximized(!isMaximized)}>
                  {isMaximized ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
                </Button>
              </TooltipTrigger>
              <TooltipContent>{isMaximized ? "Minimize" : "Maximize"}</TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="h-7 w-7 text-zinc-400 hover:text-red-400" onClick={() => onOpenChange(false)}>
                  <X className="h-3.5 w-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Close</TooltipContent>
            </Tooltip>
          </div>
        </div>

        {/* ── Quick Commands Bar ── */}
        <div className="flex items-center gap-1.5 px-4 py-1.5 bg-zinc-900/60 border-b border-zinc-800 overflow-x-auto shrink-0">
          <span className="text-[9px] text-zinc-500 uppercase shrink-0 mr-1">Quick:</span>
          {(exploitContext ? SUGGESTED_COMMANDS.slice(0, 6) : NMAP_SUGGESTIONS.map(s => ({
            label: s.label,
            cmd: typeof s.cmd === "function" ? s.cmd(selectedAsset || assets[0]?.hostname || "TARGET") : s.cmd,
          }))).map((s) => (
            <button
              key={s.label}
              onClick={() => {
                const cmd = typeof s.cmd === "string" ? s.cmd : s.cmd;
                setCurrentCmd(cmd);
                inputRef.current?.focus();
              }}
              className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 hover:bg-green-900/30 hover:text-green-400 border border-zinc-700 hover:border-green-500/30 transition-colors whitespace-nowrap"
            >
              {s.label}
            </button>
          ))}
          {!exploitContext && (
            <>
              <span className="text-zinc-700 mx-1">|</span>
              {SUGGESTED_COMMANDS.slice(0, 5).map((s) => (
                <button
                  key={s.label}
                  onClick={() => {
                    setCurrentCmd(s.cmd);
                    inputRef.current?.focus();
                  }}
                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 hover:bg-green-900/30 hover:text-green-400 border border-zinc-700 hover:border-green-500/30 transition-colors whitespace-nowrap"
                >
                  {s.label}
                </button>
              ))}
            </>
          )}
        </div>

        {/* ── Output Area ── */}
        <div ref={outputRef} className="flex-1 overflow-auto px-4 py-2 font-mono text-[12px] min-h-0">
          {entries.length === 0 && (
            <div className="text-zinc-500 py-4">
              <div className="text-green-400/60 mb-2">
                {exploitContext
                  ? `Shell session on ${exploitContext.targetHost}. Type commands to interact.`
                  : `Pentest terminal for engagement #${engagementId}. Commands execute on the scan server.`}
              </div>
              <div className="text-zinc-600 text-[11px]">
                Use arrow keys for command history. Ctrl+L to clear. Ctrl+C to cancel input.
              </div>
            </div>
          )}
          {entries.map((entry) => (
            <div key={entry.id} className="mb-2">
              {entry.command && (
                <div className="flex items-center gap-2">
                  <span className="text-green-400 select-none">
                    {selectedAsset ? `root@${selectedAsset.split(".")[0]}` : "pentest"}
                    <span className="text-zinc-500">:</span>
                    <span className="text-blue-400">~</span>
                    <span className="text-zinc-500">$</span>
                  </span>
                  <span className="text-zinc-100">{entry.command}</span>
                  {entry.isRunning && <Loader2 className="h-3 w-3 text-green-400 animate-spin" />}
                  {!entry.isRunning && entry.exitCode !== 0 && entry.command && (
                    <span className="text-[9px] text-red-400">[exit:{entry.exitCode}]</span>
                  )}
                  {!entry.isRunning && entry.durationMs > 0 && (
                    <span className="text-[9px] text-zinc-600">{entry.durationMs}ms</span>
                  )}
                </div>
              )}
              {entry.output && (
                <pre className="text-zinc-300 whitespace-pre-wrap break-words ml-0 mt-0.5 leading-relaxed">{entry.output}</pre>
              )}
              {entry.stderr && (
                <pre className="text-red-400/80 whitespace-pre-wrap break-words ml-0 mt-0.5 leading-relaxed">{entry.stderr}</pre>
              )}
            </div>
          ))}
        </div>

        {/* ── Input Line ── */}
        <div className="flex items-center gap-2 px-4 py-2 bg-zinc-900/80 border-t border-zinc-800 shrink-0">
          <span className="text-green-400 font-mono text-[12px] select-none shrink-0">
            {selectedAsset ? `root@${selectedAsset.split(".")[0]}` : "pentest"}
            <span className="text-zinc-500">:</span>
            <span className="text-blue-400">~</span>
            <span className="text-zinc-500">$</span>
          </span>
          <input
            ref={inputRef}
            type="text"
            value={currentCmd}
            onChange={(e) => setCurrentCmd(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a command..."
            className="flex-1 bg-transparent text-zinc-100 font-mono text-[12px] outline-none placeholder:text-zinc-600"
            autoFocus
            spellCheck={false}
            autoComplete="off"
          />
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-green-400 hover:bg-green-900/30"
            onClick={() => executeCommand(currentCmd)}
            disabled={!currentCmd.trim() || runCommandMut.isPending}
          >
            {runCommandMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
          </Button>
        </div>
      </div>
    </TooltipProvider>
  );
}
