import { useState, useEffect, useRef, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { toast } from "sonner";
import {
  Terminal,
  Monitor,
  Skull,
  Shield,
  Server,
  RefreshCw,
  Trash2,
  Send,
  ArrowUpCircle,
  Wifi,
  WifiOff,
  Copy,
  X,
  Maximize2,
  Minimize2,
  ChevronRight,
} from "lucide-react";
import ROEWarningBanner from "@/components/ROEWarningBanner";
import AppShell from "@/components/AppShell";

interface SessionEntry {
  serverId: number;
  serverName: string;
  sessionId: string;
  type: string;
  info: string;
  targetHost: string;
  username: string;
  platform: string;
  arch: string;
  via_exploit: string;
  via_payload: string;
  tunnel_local: string;
  tunnel_peer: string;
  desc: string;
  uuid: string;
  exploit_uuid: string;
  routes: string;
}

// Interactive terminal component
function SessionTerminal({
  session,
  onClose,
  isFullscreen,
  onToggleFullscreen,
}: {
  session: SessionEntry;
  onClose: () => void;
  isFullscreen: boolean;
  onToggleFullscreen: () => void;
}) {
  const [command, setCommand] = useState("");
  const [output, setOutput] = useState<string[]>([]);
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const sessionType = session.type === "meterpreter" ? "meterpreter" as const : "shell" as const;

  const writeMut = trpc.msfSessions.write.useMutation({
    onSuccess: () => {
      // Command sent, output will come from polling
    },
    onError: (err) => {
      setOutput(prev => [...prev, `\x1b[31m[ERROR] ${err.message}\x1b[0m\n`]);
    },
  });

  // Poll for output
  const { data: readData } = trpc.msfSessions.read.useQuery(
    { serverId: session.serverId, sessionId: session.sessionId, sessionType },
    { refetchInterval: 1500, enabled: true }
  );

  useEffect(() => {
    if (readData?.data) {
      setOutput(prev => [...prev, readData.data]);
    }
  }, [readData?.data]);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [output]);

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const sendCommand = useCallback(() => {
    if (!command.trim()) return;

    setOutput(prev => [...prev, `\n${sessionType === "meterpreter" ? "meterpreter > " : "$ "}${command}\n`]);
    setCommandHistory(prev => [...prev, command]);
    setHistoryIndex(-1);

    writeMut.mutate({
      serverId: session.serverId,
      sessionId: session.sessionId,
      sessionType,
      command: command.trim(),
    });

    setCommand("");
  }, [command, session, sessionType, writeMut]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      sendCommand();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (commandHistory.length > 0) {
        const newIndex = historyIndex === -1 ? commandHistory.length - 1 : Math.max(0, historyIndex - 1);
        setHistoryIndex(newIndex);
        setCommand(commandHistory[newIndex]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIndex >= 0) {
        const newIndex = historyIndex + 1;
        if (newIndex >= commandHistory.length) {
          setHistoryIndex(-1);
          setCommand("");
        } else {
          setHistoryIndex(newIndex);
          setCommand(commandHistory[newIndex]);
        }
      }
    }
  };

  const prompt = sessionType === "meterpreter" ? "meterpreter > " : "$ ";

  return (
    <div className={`flex flex-col ${isFullscreen ? "fixed inset-0 z-50 bg-background" : "h-[500px]"}`}>
      {/* Terminal Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-zinc-900 border-b border-zinc-700 rounded-t-lg">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500 cursor-pointer hover:bg-red-400" onClick={onClose} />
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <div className="w-3 h-3 rounded-full bg-green-500" />
          </div>
          <span className="text-xs text-zinc-400 font-mono">
            {session.type === "meterpreter" ? "meterpreter" : "shell"} — {session.targetHost} — Session #{session.sessionId}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className={`text-xs ${session.type === "meterpreter" ? "text-purple-400 border-purple-400/30" : "text-green-400 border-green-400/30"}`}>
            {session.type === "meterpreter" ? <Shield className="h-3 w-3 mr-1" /> : <Terminal className="h-3 w-3 mr-1" />}
            {session.type}
          </Badge>
          <Button variant="ghost" size="icon" className="h-6 w-6 text-zinc-400 hover:text-white" onClick={onToggleFullscreen}>
            {isFullscreen ? <Minimize2 className="h-3 w-3" /> : <Maximize2 className="h-3 w-3" />}
          </Button>
          <Button variant="ghost" size="icon" className="h-6 w-6 text-zinc-400 hover:text-white" onClick={onClose}>
            <X className="h-3 w-3" />
          </Button>
        </div>
      </div>

      {/* Terminal Body */}
      <div
        ref={terminalRef}
        className="flex-1 bg-zinc-950 p-4 font-mono text-sm text-green-400 overflow-y-auto whitespace-pre-wrap"
        onClick={() => inputRef.current?.focus()}
      >
        {/* Welcome banner */}
        <div className="text-zinc-500 mb-2">
          {session.type === "meterpreter" ? (
            <>
              <span className="text-purple-400">╔══════════════════════════════════════╗</span>{"\n"}
              <span className="text-purple-400">║</span> <span className="text-white">Meterpreter Session #{session.sessionId}</span>{" ".repeat(Math.max(0, 17 - session.sessionId.length))}<span className="text-purple-400">║</span>{"\n"}
              <span className="text-purple-400">╚══════════════════════════════════════╝</span>{"\n"}
            </>
          ) : (
            <>
              <span className="text-green-500">╔══════════════════════════════════════╗</span>{"\n"}
              <span className="text-green-500">║</span> <span className="text-white">Shell Session #{session.sessionId}</span>{" ".repeat(Math.max(0, 23 - session.sessionId.length))}<span className="text-green-500">║</span>{"\n"}
              <span className="text-green-500">╚══════════════════════════════════════╝</span>{"\n"}
            </>
          )}
          Target: {session.targetHost} ({session.platform} {session.arch}){"\n"}
          Via: {session.via_exploit}{"\n"}
          User: {session.username}{"\n"}
          {"─".repeat(40)}{"\n"}
        </div>

        {/* Output */}
        {output.map((line, i) => (
          <span key={i} className={line.includes("[ERROR]") ? "text-red-400" : "text-green-300"}>
            {line}
          </span>
        ))}

        {/* Input line */}
        <div className="flex items-center mt-1">
          <span className="text-amber-400 mr-1">{prompt}</span>
          <Input
            ref={inputRef}
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            onKeyDown={handleKeyDown}
            className="bg-transparent border-none text-green-300 font-mono text-sm p-0 h-auto focus-visible:ring-0 focus-visible:ring-offset-0 placeholder:text-zinc-600"
            placeholder="Type command..."
            disabled={writeMut.isPending}
          />
        </div>
      </div>

      {/* Terminal Footer */}
      <div className="flex items-center justify-between px-4 py-2 bg-zinc-900 border-t border-zinc-700 rounded-b-lg">
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <Wifi className="h-3 w-3 text-green-500" />
          <span>Connected via SSH tunnel</span>
          <span>•</span>
          <span>Server: {session.serverName}</span>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs text-zinc-400"
            onClick={() => {
              navigator.clipboard.writeText(output.join(""));
              toast.info("Terminal output copied");
            }}
          >
            <Copy className="h-3 w-3 mr-1" />
            Copy Output
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs text-zinc-400"
            onClick={() => setOutput([])}
          >
            Clear
          </Button>
          <Button
            size="sm"
            className="h-7 text-xs"
            onClick={sendCommand}
            disabled={!command.trim() || writeMut.isPending}
          >
            <Send className="h-3 w-3 mr-1" />
            Send
          </Button>
        </div>
      </div>
    </div>
  );
}

export default function MsfSessions() {
  const [activeSession, setActiveSession] = useState<SessionEntry | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [confirmKill, setConfirmKill] = useState<SessionEntry | null>(null);

  const utils = trpc.useUtils();
  const { data: sessions, isLoading, refetch } = trpc.msfSessions.listAll.useQuery(undefined, {
    refetchInterval: 10000, // Poll every 10 seconds
  });

  const stopMut = trpc.msfSessions.stop.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      utils.msfSessions.listAll.invalidate();
      setConfirmKill(null);
      if (activeSession?.sessionId === confirmKill?.sessionId) {
        setActiveSession(null);
      }
    },
    onError: (err) => toast.error("Failed to kill session", { description: err.message }),
  });

  const upgradeMut = trpc.msfSessions.upgradeToMeterpreter.useMutation({
    onSuccess: () => {
      toast.success("Upgrade initiated", { description: "Check sessions list for new Meterpreter session" });
      setTimeout(() => utils.msfSessions.listAll.invalidate(), 5000);
    },
    onError: (err) => toast.error("Upgrade failed", { description: err.message }),
  });

  const sessionsByServer = sessions?.reduce((acc, s) => {
    if (!acc[s.serverName]) acc[s.serverName] = [];
    acc[s.serverName].push(s);
    return acc;
  }, {} as Record<string, SessionEntry[]>) || {};

  const totalSessions = sessions?.length || 0;
  const meterpreterCount = sessions?.filter(s => s.type === "meterpreter").length || 0;
  const shellCount = sessions?.filter(s => s.type === "shell").length || 0;

  return (
    <AppShell activePath="/msf-sessions">
      <div className="space-y-6">
      {/* ROE Warning Banner */}
      <ROEWarningBanner riskTier="red" operationName="Exploitation / Session Interaction" />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Terminal className="h-6 w-6 text-green-500" />
            Live Sessions
          </h1>
          <p className="text-muted-foreground mt-1">
            Real-time Meterpreter and shell session monitoring with interactive terminal
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Sessions</p>
                <p className="text-3xl font-bold">{totalSessions}</p>
              </div>
              <Monitor className="h-8 w-8 text-blue-500/50" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Meterpreter</p>
                <p className="text-3xl font-bold text-purple-400">{meterpreterCount}</p>
              </div>
              <Shield className="h-8 w-8 text-purple-500/50" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Shell</p>
                <p className="text-3xl font-bold text-green-400">{shellCount}</p>
              </div>
              <Terminal className="h-8 w-8 text-green-500/50" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Active Terminal */}
      {activeSession && (
        <Card className="overflow-hidden border-green-500/30">
          <SessionTerminal
            session={activeSession}
            onClose={() => { setActiveSession(null); setIsFullscreen(false); }}
            isFullscreen={isFullscreen}
            onToggleFullscreen={() => setIsFullscreen(!isFullscreen)}
          />
        </Card>
      )}

      {/* Session List */}
      {isLoading ? (
        <Card>
          <CardContent className="py-12 text-center">
            <RefreshCw className="h-8 w-8 animate-spin mx-auto text-muted-foreground/50 mb-3" />
            <p className="text-muted-foreground">Polling MSF servers for active sessions...</p>
          </CardContent>
        </Card>
      ) : totalSessions === 0 ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <WifiOff className="h-12 w-12 text-muted-foreground/50 mb-4" />
            <h3 className="text-lg font-semibold">No Active Sessions</h3>
            <p className="text-muted-foreground mt-1 max-w-md">
              No Meterpreter or shell sessions are currently active across your MSF servers.
              Fire an exploit from the Exploit Catalog to establish a session.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {Object.entries(sessionsByServer).map(([serverName, serverSessions]) => (
            <Card key={serverName}>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Server className="h-4 w-4 text-blue-500" />
                  {serverName}
                  <Badge variant="secondary" className="text-xs">{serverSessions.length} session{serverSessions.length !== 1 ? "s" : ""}</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {serverSessions.map((session) => (
                    <div
                      key={`${session.serverId}-${session.sessionId}`}
                      className={`flex items-center justify-between p-3 rounded-lg border transition-colors cursor-pointer hover:bg-muted/50 ${
                        activeSession?.sessionId === session.sessionId && activeSession?.serverId === session.serverId
                          ? "border-green-500/50 bg-green-500/5"
                          : "border-border/50"
                      }`}
                      onClick={() => setActiveSession(session)}
                    >
                      <div className="flex items-center gap-3">
                        {session.type === "meterpreter" ? (
                          <Shield className="h-5 w-5 text-purple-400" />
                        ) : (
                          <Terminal className="h-5 w-5 text-green-400" />
                        )}
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sm font-medium">
                              Session #{session.sessionId}
                            </span>
                            <Badge
                              variant="outline"
                              className={`text-xs ${
                                session.type === "meterpreter"
                                  ? "text-purple-400 border-purple-400/30"
                                  : "text-green-400 border-green-400/30"
                              }`}
                            >
                              {session.type}
                            </Badge>
                            <Badge variant="secondary" className="text-xs">
                              {session.platform} {session.arch}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                            <span>{session.targetHost}</span>
                            <span>•</span>
                            <span>{session.username}</span>
                            {session.via_exploit && (
                              <>
                                <span>•</span>
                                <span className="truncate max-w-[200px]">{session.via_exploit}</span>
                              </>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          className="text-xs"
                          onClick={(e) => {
                            e.stopPropagation();
                            setActiveSession(session);
                          }}
                        >
                          <ChevronRight className="h-3 w-3 mr-1" />
                          Interact
                        </Button>
                        {session.type === "shell" && (
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs text-purple-400 hover:text-purple-300"
                            onClick={(e) => {
                              e.stopPropagation();
                              upgradeMut.mutate({ serverId: session.serverId, sessionId: session.sessionId });
                            }}
                            disabled={upgradeMut.isPending}
                          >
                            <ArrowUpCircle className="h-3 w-3 mr-1" />
                            Upgrade
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-xs text-destructive hover:text-destructive"
                          onClick={(e) => {
                            e.stopPropagation();
                            setConfirmKill(session);
                          }}
                        >
                          <Skull className="h-3 w-3 mr-1" />
                          Kill
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Kill Confirmation Dialog */}
      <Dialog open={!!confirmKill} onOpenChange={() => setConfirmKill(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <Skull className="h-5 w-5" />
              Kill Session #{confirmKill?.sessionId}?
            </DialogTitle>
            <DialogDescription>
              This will terminate the {confirmKill?.type} session on {confirmKill?.targetHost}.
              This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <div className="bg-muted/50 rounded-md p-3 text-sm font-mono">
            <p>Target: {confirmKill?.targetHost}</p>
            <p>User: {confirmKill?.username}</p>
            <p>Type: {confirmKill?.type}</p>
            <p>Exploit: {confirmKill?.via_exploit}</p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmKill(null)}>Cancel</Button>
            <Button
              variant="destructive"
              onClick={() => confirmKill && stopMut.mutate({ serverId: confirmKill.serverId, sessionId: confirmKill.sessionId })}
              disabled={stopMut.isPending}
            >
              {stopMut.isPending ? "Killing..." : "Kill Session"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
    </AppShell>
  );
}
