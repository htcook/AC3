import { useState, useRef, useEffect, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { toast } from "sonner";
import {
  Play,
  Square,
  Trash2,
  Clock,
  HardDrive,
  Terminal,
  Monitor,
  ChevronLeft,
  ChevronRight,
  Pause,
  SkipForward,
  SkipBack,
  Maximize2,
  Minimize2,
  Circle,
  Download,
} from "lucide-react";
import AppShell from "@/components/AppShell";

function formatDuration(ms: number): string {
  if (!ms) return "0s";
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(date: string | Date | null): string {
  if (!date) return "—";
  return new Date(date).toLocaleString();
}

// ─── Playback Viewer Component ───────────────────────────────────────────────

function PlaybackViewer({
  recordingId,
  onClose,
}: {
  recordingId: number;
  onClose: () => void;
}) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const [currentChunkIdx, setCurrentChunkIdx] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [displayedContent, setDisplayedContent] = useState("");
  const playbackTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { data: playbackData, isLoading } =
    trpc.sessionRecordings.getPlaybackData.useQuery({ recordingId });

  const chunks = playbackData?.chunks || [];
  const recording = playbackData?.recording;
  const totalDuration = playbackData?.totalDurationMs || 0;

  // Calculate current time position
  const currentTime =
    currentChunkIdx < chunks.length
      ? chunks[currentChunkIdx]?.timestampMs || 0
      : totalDuration;

  // Build displayed content up to current chunk
  useEffect(() => {
    if (!chunks.length) return;
    let content = "";
    for (let i = 0; i <= currentChunkIdx && i < chunks.length; i++) {
      const chunk = chunks[i];
      if (chunk.chunkType === "system") {
        content += `\n\x1b[90m${chunk.content}\x1b[0m\n`;
      } else if (chunk.chunkType === "input") {
        content += `\x1b[32m$ ${chunk.content}\x1b[0m\n`;
      } else {
        content += chunk.content;
      }
    }
    setDisplayedContent(content);
  }, [currentChunkIdx, chunks]);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [displayedContent]);

  // Playback engine
  useEffect(() => {
    if (!isPlaying || currentChunkIdx >= chunks.length - 1) {
      if (isPlaying && currentChunkIdx >= chunks.length - 1) setIsPlaying(false);
      return;
    }

    const currentTs = chunks[currentChunkIdx]?.timestampMs || 0;
    const nextTs = chunks[currentChunkIdx + 1]?.timestampMs || 0;
    const delay = Math.max(50, (nextTs - currentTs) / playbackSpeed);

    playbackTimerRef.current = setTimeout(() => {
      setCurrentChunkIdx((prev) => prev + 1);
    }, delay);

    return () => {
      if (playbackTimerRef.current) clearTimeout(playbackTimerRef.current);
    };
  }, [isPlaying, currentChunkIdx, chunks, playbackSpeed]);

  const handlePlay = () => {
    if (currentChunkIdx >= chunks.length - 1) setCurrentChunkIdx(0);
    setIsPlaying(true);
  };

  const handlePause = () => setIsPlaying(false);

  const handleSeek = (chunkIdx: number) => {
    setIsPlaying(false);
    setCurrentChunkIdx(Math.max(0, Math.min(chunkIdx, chunks.length - 1)));
  };

  const handleExport = () => {
    if (!chunks.length) return;
    let text = "";
    for (const chunk of chunks) {
      if (chunk.chunkType === "system") text += `[SYSTEM] ${chunk.content}\n`;
      else if (chunk.chunkType === "input") text += `$ ${chunk.content}\n`;
      else text += chunk.content;
    }
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `recording-${recordingId}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Recording exported as text file");
  };

  const progressPercent = chunks.length > 0 ? (currentChunkIdx / (chunks.length - 1)) * 100 : 0;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500" />
      </div>
    );
  }

  return (
    <div className={`flex flex-col ${isFullscreen ? "fixed inset-0 z-50 bg-black" : ""}`}>
      {/* Header */}
      <div className="flex items-center justify-between p-3 bg-zinc-900 border-b border-zinc-700">
        <div className="flex items-center gap-3">
          <Badge variant="outline" className="text-red-400 border-red-400/30">
            {recording?.sessionType === "meterpreter" ? "Meterpreter" : "Shell"}
          </Badge>
          <span className="text-sm text-zinc-400">
            {recording?.targetHost || "Unknown target"} • Session {recording?.sessionId}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={handleExport} title="Export as text">
            <Download className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsFullscreen(!isFullscreen)}
          >
            {isFullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
          </Button>
          {!isFullscreen && (
            <Button variant="ghost" size="sm" onClick={onClose}>
              ✕
            </Button>
          )}
        </div>
      </div>

      {/* Terminal Output */}
      <div
        ref={terminalRef}
        className={`bg-black font-mono text-sm text-green-400 p-4 overflow-auto whitespace-pre-wrap ${
          isFullscreen ? "flex-1" : "h-[400px]"
        }`}
      >
        {displayedContent || (
          <span className="text-zinc-600">Press play to start playback...</span>
        )}
      </div>

      {/* Progress Bar */}
      <div className="px-3 py-2 bg-zinc-900">
        <div
          className="relative h-2 bg-zinc-700 rounded-full cursor-pointer"
          onClick={(e) => {
            const rect = e.currentTarget.getBoundingClientRect();
            const pct = (e.clientX - rect.left) / rect.width;
            handleSeek(Math.round(pct * (chunks.length - 1)));
          }}
        >
          <div
            className="absolute h-full bg-red-500 rounded-full transition-all duration-100"
            style={{ width: `${progressPercent}%` }}
          />
          <div
            className="absolute top-1/2 -translate-y-1/2 w-3 h-3 bg-white rounded-full shadow-lg transition-all duration-100"
            style={{ left: `calc(${progressPercent}% - 6px)` }}
          />
        </div>
        <div className="flex justify-between text-xs text-zinc-500 mt-1">
          <span>{formatDuration(currentTime)}</span>
          <span>
            Chunk {currentChunkIdx + 1} / {chunks.length}
          </span>
          <span>{formatDuration(totalDuration)}</span>
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center justify-between px-3 py-2 bg-zinc-900 border-t border-zinc-700">
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleSeek(0)}
            title="Jump to start"
          >
            <SkipBack className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleSeek(currentChunkIdx - 10)}
            title="Back 10 chunks"
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          {isPlaying ? (
            <Button
              variant="outline"
              size="sm"
              onClick={handlePause}
              className="bg-red-500/20 border-red-500/50 text-red-400"
            >
              <Pause className="h-4 w-4 mr-1" /> Pause
            </Button>
          ) : (
            <Button
              variant="outline"
              size="sm"
              onClick={handlePlay}
              className="bg-green-500/20 border-green-500/50 text-green-400"
            >
              <Play className="h-4 w-4 mr-1" /> Play
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleSeek(currentChunkIdx + 10)}
            title="Forward 10 chunks"
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleSeek(chunks.length - 1)}
            title="Jump to end"
          >
            <SkipForward className="h-4 w-4" />
          </Button>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-zinc-500">Speed:</span>
          {[0.5, 1, 2, 5, 10].map((speed) => (
            <Button
              key={speed}
              variant={playbackSpeed === speed ? "default" : "ghost"}
              size="sm"
              className={`text-xs h-6 px-2 ${
                playbackSpeed === speed ? "bg-red-600 text-white" : ""
              }`}
              onClick={() => setPlaybackSpeed(speed)}
            >
              {speed}x
            </Button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function SessionRecordings() {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedRecording, setSelectedRecording] = useState<number | null>(null);
  const utils = trpc.useUtils();

  const { data: recordingsData, isLoading } =
    trpc.sessionRecordings.listRecordings.useQuery({
      status: statusFilter !== "all" ? (statusFilter as any) : undefined,
      limit: 50,
    });

  const { data: activeRecordings } =
    trpc.sessionRecordings.getActiveRecordings.useQuery(undefined, {
      refetchInterval: 5000,
    });

  const deleteRecording = trpc.sessionRecordings.deleteRecording.useMutation({
    onSuccess: () => {
      toast.success("Recording deleted successfully");
      utils.sessionRecordings.listRecordings.invalidate();
    },
    onError: (err) => {
      toast.error(err.message);
    },
  });

  const recordings = recordingsData?.items || [];

  return (
    <AppShell activePath="/session-recordings">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Monitor className="h-6 w-6 text-red-500" />
            Session Recordings
          </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Review recorded operator sessions from active engagements. Each recording captures the commands executed, outputs received, and timestamps for every action taken during a red team operation. Use these recordings for quality assurance, training, evidence documentation, and post-engagement review. Filter by operator, engagement, or date range to find specific sessions.</p>
          <p className="text-zinc-400 text-sm mt-1">
            Review and replay past session interactions for evidence and reporting
          </p>
        </div>
        {activeRecordings && activeRecordings.length > 0 && (
          <Badge className="bg-red-500/20 text-red-400 border-red-500/30 animate-pulse">
            <Circle className="h-2 w-2 mr-1 fill-red-500" />
            {activeRecordings.length} Active Recording{activeRecordings.length > 1 ? "s" : ""}
          </Badge>
        )}
      </div>

      {/* Active Recordings Banner */}
      {activeRecordings && activeRecordings.length > 0 && (
        <Card className="bg-red-500/10 border-red-500/30">
          <CardContent className="p-4">
            <h3 className="text-sm font-medium text-red-400 mb-2">Active Recordings</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {activeRecordings.map((rec) => (
                <div
                  key={rec.key}
                  className="flex items-center justify-between bg-zinc-900/50 rounded-lg p-3"
                >
                  <div>
                    <span className="text-sm text-white">Session {rec.sessionId}</span>
                    <div className="text-xs text-zinc-500">
                      Server {rec.serverId} • {rec.chunkCount} chunks •{" "}
                      {formatBytes(rec.totalBytes)}
                    </div>
                  </div>
                  <Badge variant="outline" className="text-red-400 border-red-400/30 animate-pulse">
                    <Circle className="h-2 w-2 mr-1 fill-red-500" />
                    {formatDuration(rec.durationMs)}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40 bg-zinc-800 border-zinc-700">
            <SelectValue placeholder="Filter by status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="recording">Recording</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="error">Error</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-sm text-zinc-500">
          {recordingsData?.total || 0} recording{(recordingsData?.total || 0) !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Recordings List */}
      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Card key={i} className="bg-zinc-800/50 border-zinc-700 animate-pulse">
              <CardContent className="p-6 h-40" />
            </Card>
          ))}
        </div>
      ) : recordings.length === 0 ? (
        <Card className="bg-zinc-800/50 border-zinc-700">
          <CardContent className="p-12 text-center">
            <Monitor className="h-12 w-12 text-zinc-600 mx-auto mb-3" />
            <h3 className="text-lg font-medium text-zinc-400">No Recordings Yet</h3>
            <p className="text-sm text-zinc-500 mt-1">
              Session recordings will appear here when you start recording active sessions.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {recordings.map((rec) => (
            <Card
              key={rec.id}
              className="bg-zinc-800/50 border-zinc-700 hover:border-zinc-600 transition-colors cursor-pointer"
              onClick={() => setSelectedRecording(rec.id)}
            >
              <CardContent className="p-4">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-red-400" />
                    <span className="font-medium text-white">
                      Session {rec.sessionId}
                    </span>
                  </div>
                  <Badge
                    variant="outline"
                    className={
                      rec.status === "recording"
                        ? "text-red-400 border-red-400/30 animate-pulse"
                        : rec.status === "completed"
                        ? "text-green-400 border-green-400/30"
                        : "text-yellow-400 border-yellow-400/30"
                    }
                  >
                    {rec.status === "recording" && <Circle className="h-2 w-2 mr-1 fill-red-500" />}
                    {rec.status}
                  </Badge>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs text-zinc-400 mb-3">
                  <div className="flex items-center gap-1">
                    <Monitor className="h-3 w-3" />
                    {rec.targetHost || "Unknown"}
                  </div>
                  <div className="flex items-center gap-1">
                    <Terminal className="h-3 w-3" />
                    {rec.sessionType}
                  </div>
                  <div className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {formatDuration(rec.durationMs || 0)}
                  </div>
                  <div className="flex items-center gap-1">
                    <HardDrive className="h-3 w-3" />
                    {formatBytes(rec.totalBytes)} • {rec.totalChunks} chunks
                  </div>
                </div>

                {rec.viaExploit && (
                  <div className="text-xs text-zinc-500 mb-2 truncate">
                    Exploit: {rec.viaExploit}
                  </div>
                )}

                <div className="flex items-center justify-between">
                  <span className="text-xs text-zinc-500">
                    {formatDate(rec.startedAt)}
                  </span>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 text-xs text-green-400 hover:text-green-300"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedRecording(rec.id);
                      }}
                    >
                      <Play className="h-3 w-3 mr-1" /> Replay
                    </Button>
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs text-red-400 hover:text-red-300"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Delete Recording?</AlertDialogTitle>
                          <AlertDialogDescription>
                            This will permanently delete the recording and all its chunks.
                            This action cannot be undone.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction
                            className="bg-red-600 hover:bg-red-700"
                            onClick={() => deleteRecording.mutate({ recordingId: rec.id })}
                          >
                            Delete
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Playback Dialog */}
      <Dialog
        open={selectedRecording !== null}
        onOpenChange={(open) => !open && setSelectedRecording(null)}
      >
        <DialogContent className="max-w-4xl p-0 bg-zinc-900 border-zinc-700 overflow-hidden">
          {selectedRecording && (
            <PlaybackViewer
              recordingId={selectedRecording}
              onClose={() => setSelectedRecording(null)}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
    </AppShell>
  );
}
