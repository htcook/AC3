/**
 * Global AI Chat Widget — role-specialized floating chat panel with:
 *   1. Chat session persistence (create/resume/archive sessions)
 *   2. Quick action result cards from AI tool-calling
 *   3. Admin persona switching preview mode
 *
 * Button positioned top-right to avoid overlapping sidebar navigation.
 */
import { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import {
  MessageCircle, X, Send, Loader2, AlertTriangle, Key,
  Minimize2, Maximize2, Trash2, Bot, Zap, ChevronLeft,
  Plus, Archive, Clock, PanelLeftClose, PanelLeftOpen,
  CheckCircle2, XCircle, Shield, Target, Eye, Globe,
  Users, BarChart3, FileText, Cpu, Pencil,
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import { Streamdown } from "streamdown";
import { useLocation } from "wouter";

interface ChatMessage {
  role: "user" | "assistant" | "tool";
  content: string;
  timestamp: number;
  toolName?: string;
  toolResult?: any;
}

const ICON_MAP: Record<string, React.ComponentType<{ className?: string }>> = {
  Shield, Target, Eye, Globe, Users, BarChart3, FileText, Cpu, AlertTriangle, Key,
};

const ROLE_ACCENTS: Record<string, string> = {
  operator: "from-red-500/20 to-orange-500/10 border-red-500/30",
  executive: "from-blue-500/20 to-indigo-500/10 border-blue-500/30",
  analyst: "from-emerald-500/20 to-teal-500/10 border-emerald-500/30",
  team_lead: "from-amber-500/20 to-yellow-500/10 border-amber-500/30",
  client: "from-violet-500/20 to-purple-500/10 border-violet-500/30",
  admin: "from-cyan-500/20 to-sky-500/10 border-cyan-500/30",
};

const ROLE_ICON_COLORS: Record<string, string> = {
  operator: "text-red-400 bg-red-500/10",
  executive: "text-blue-400 bg-blue-500/10",
  analyst: "text-emerald-400 bg-emerald-500/10",
  team_lead: "text-amber-400 bg-amber-500/10",
  client: "text-violet-400 bg-violet-500/10",
  admin: "text-cyan-400 bg-cyan-500/10",
};

const ROLE_LABELS: Record<string, string> = {
  operator: "Operator",
  executive: "Executive",
  analyst: "Analyst",
  team_lead: "Team Lead",
  client: "Client",
  admin: "Admin",
};

export function GlobalAiChat() {
  const [isOpen, setIsOpen] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [showSidebar, setShowSidebar] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [includeErrors, setIncludeErrors] = useState(false);
  const [includeCreds, setIncludeCreds] = useState(false);
  const [includeKnowledgeBase, setIncludeKnowledgeBase] = useState(true);
  const [activeSessionId, setActiveSessionId] = useState<number | null>(null);
  const [personaOverride, setPersonaOverride] = useState<string | undefined>(undefined);
  const [showPersonaPicker, setShowPersonaPicker] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const [location] = useLocation();

  // Fetch role-specific chat configuration
  const configInput = useMemo(() => personaOverride ? { personaOverride } : undefined, [personaOverride]);
  const { data: chatConfig } = trpc.aiChat.getConfig.useQuery(configInput, {
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: 30_000,
  });

  // Session list
  const { data: sessions, refetch: refetchSessions } = trpc.aiChat.listSessions.useQuery(undefined, {
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: 10_000,
    enabled: isOpen,
  });

  const createSessionMut = trpc.aiChat.createSession.useMutation({
    onSuccess: (session) => {
      setActiveSessionId(session.id);
      setMessages([]);
      refetchSessions();
    },
  });

  const archiveSessionMut = trpc.aiChat.archiveSession.useMutation({
    onSuccess: () => {
      if (activeSessionId) {
        setActiveSessionId(null);
        setMessages([]);
      }
      refetchSessions();
    },
  });

  const deleteSessionMut = trpc.aiChat.deleteSession.useMutation({
    onSuccess: () => {
      setActiveSessionId(null);
      setMessages([]);
      refetchSessions();
    },
  });

  const renameSessionMut = trpc.aiChat.renameSession.useMutation({
    onSuccess: () => refetchSessions(),
  });

  // Load messages when session changes
  const { data: sessionData } = trpc.aiChat.loadMessages.useQuery(
    { sessionId: activeSessionId! },
    { enabled: !!activeSessionId, retry: false, refetchOnWindowFocus: false }
  );

  useEffect(() => {
    if (sessionData?.messages) {
      setMessages(
        sessionData.messages.map((m) => ({
          role: m.role as "user" | "assistant" | "tool",
          content: m.content,
          timestamp: new Date(m.createdAt).getTime(),
          toolName: m.toolName || undefined,
          toolResult: m.toolResult || undefined,
        }))
      );
    }
  }, [sessionData]);

  const role = chatConfig?.role || "operator";
  const accent = ROLE_ACCENTS[role] || ROLE_ACCENTS.operator;
  const iconColor = ROLE_ICON_COLORS[role] || ROLE_ICON_COLORS.operator;

  const sendMutation = trpc.aiChat.send.useMutation({
    onSuccess: (data) => {
      // Add executed action results
      if (data.executedActions && data.executedActions.length > 0) {
        for (const action of data.executedActions) {
          setMessages((prev) => [
            ...prev,
            {
              role: "tool",
              content: action.result?.message || "Action executed",
              timestamp: Date.now(),
              toolName: action.displayName,
              toolResult: action.result,
            },
          ]);
        }
      }
      if (data.reply) {
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: data.reply!, timestamp: Date.now() },
        ]);
      } else if (data.error) {
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: `\u26a0\ufe0f ${data.error}`, timestamp: Date.now() },
        ]);
      }
      // Update session ID if a new one was created
      if (data.sessionId && !activeSessionId) {
        setActiveSessionId(data.sessionId);
      }
      refetchSessions();
    },
    onError: (err) => {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: `\u26a0\ufe0f Connection error: ${err.message}`, timestamp: Date.now() },
      ]);
    },
  });

  useEffect(() => {
    if (scrollRef.current) {
      requestAnimationFrame(() => {
        scrollRef.current!.scrollTop = scrollRef.current!.scrollHeight;
      });
    }
  }, [messages, sendMutation.isPending]);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [isOpen]);

  const handleSend = useCallback(() => {
    const trimmed = input.trim();
    if (!trimmed || sendMutation.isPending) return;

    const newMsg: ChatMessage = { role: "user", content: trimmed, timestamp: Date.now() };
    setMessages((prev) => [...prev, newMsg]);
    setInput("");

    sendMutation.mutate({
      message: trimmed,
      sessionId: activeSessionId || undefined,
      conversationHistory: messages.slice(-20).filter(m => m.role !== "tool").map((m) => ({
        role: m.role as "user" | "assistant",
        content: m.content,
      })),
      currentPage: location,
      includeErrors,
      includeCreds,
      includeRoleContext: true,
      includeKnowledgeBase,
      enableToolCalling: true,
      personaOverride,
    });
  }, [input, messages, location, includeErrors, includeCreds, includeKnowledgeBase, sendMutation, activeSessionId, personaOverride]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleNewChat = () => {
    createSessionMut.mutate({ role: role });
  };

  const handleLoadSession = (sessionId: number) => {
    setActiveSessionId(sessionId);
    setShowSidebar(false);
  };

  const suggestions = useMemo(
    () => chatConfig?.suggestions || ["How can you help me?", "What's the current status?"],
    [chatConfig?.suggestions]
  );

  const hasUnread =
    messages.length > 0 && messages[messages.length - 1].role === "assistant" && !isOpen;

  return (
    <>
      {/* ── Floating Chat Button ── */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className={cn(
            "fixed top-4 right-4 z-[9999] w-11 h-11 rounded-full",
            "bg-primary text-primary-foreground shadow-lg",
            "flex items-center justify-center",
            "hover:scale-105 active:scale-95 transition-all duration-200",
            "border-2 border-primary/20",
            hasUnread && "animate-pulse ring-2 ring-primary/50"
          )}
          title={chatConfig?.assistantName || "AI Assistant"}
        >
          <Bot className="w-5 h-5" />
          {hasUnread && (
            <span className="absolute -top-1 -right-1 w-4 h-4 bg-destructive rounded-full flex items-center justify-center">
              <span className="text-[10px] text-white font-bold">!</span>
            </span>
          )}
        </button>
      )}

      {/* ── Chat Panel ── */}
      {isOpen && (
        <div
          className={cn(
            "fixed z-[9999] bg-background border border-border rounded-lg shadow-2xl flex overflow-hidden transition-all duration-200",
            isExpanded
              ? "top-4 right-4 bottom-4 left-4 md:left-auto md:w-[700px]"
              : "top-4 right-4 w-[440px] h-[75vh] max-h-[750px] min-h-[400px]"
          )}
        >
          {/* ── Session Sidebar ── */}
          {showSidebar && (
            <div className="w-[200px] border-r border-border bg-muted/30 flex flex-col flex-shrink-0">
              <div className="p-2 border-b border-border flex items-center justify-between">
                <span className="text-xs font-semibold text-muted-foreground">Chat History</span>
                <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => setShowSidebar(false)}>
                  <PanelLeftClose className="w-3.5 h-3.5" />
                </Button>
              </div>
              <div className="flex-1 overflow-y-auto">
                {sessions && sessions.length > 0 ? (
                  sessions.map((s) => (
                    <button
                      key={s.id}
                      onClick={() => handleLoadSession(s.id)}
                      className={cn(
                        "w-full text-left px-3 py-2 text-xs border-b border-border/50 hover:bg-muted/50 transition-colors group",
                        activeSessionId === s.id && "bg-primary/10"
                      )}
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="truncate font-medium text-foreground/80">{s.title || "New Chat"}</span>
                        <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button
                            onClick={(e) => { e.stopPropagation(); archiveSessionMut.mutate({ sessionId: s.id }); }}
                            className="p-0.5 hover:text-amber-500"
                            title="Archive"
                          >
                            <Archive className="w-3 h-3" />
                          </button>
                          <button
                            onClick={(e) => { e.stopPropagation(); deleteSessionMut.mutate({ sessionId: s.id }); }}
                            className="p-0.5 hover:text-destructive"
                            title="Delete"
                          >
                            <Trash2 className="w-3 h-3" />
                          </button>
                        </div>
                      </div>
                      <div className="flex items-center gap-1 mt-0.5">
                        <span className="text-[9px] text-muted-foreground capitalize">{s.role}</span>
                        <span className="text-[9px] text-muted-foreground">\u00b7 {s.messageCount || 0} msgs</span>
                      </div>
                    </button>
                  ))
                ) : (
                  <div className="p-3 text-xs text-muted-foreground text-center">No chat sessions yet</div>
                )}
              </div>
              <div className="p-2 border-t border-border">
                <Button variant="outline" size="sm" className="w-full text-xs h-7" onClick={handleNewChat}>
                  <Plus className="w-3 h-3 mr-1" /> New Chat
                </Button>
              </div>
            </div>
          )}

          {/* ── Main Chat Area ── */}
          <div className="flex flex-col flex-1 min-w-0">
            {/* ── Header ── */}
            <div className={cn("flex items-center justify-between px-3 py-2.5 border-b flex-shrink-0 bg-gradient-to-r", accent)}>
              <div className="flex items-center gap-2 min-w-0">
                {!showSidebar && (
                  <Button variant="ghost" size="icon" className="h-7 w-7 flex-shrink-0" onClick={() => setShowSidebar(true)} title="Chat history">
                    <PanelLeftOpen className="w-3.5 h-3.5" />
                  </Button>
                )}
                <div className={cn("w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0", iconColor)}>
                  <Bot className="w-3.5 h-3.5" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <h3 className="text-xs font-semibold text-foreground truncate">
                      {chatConfig?.assistantName || "AI Assistant"}
                    </h3>
                    {chatConfig?.isPersonaOverride && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 font-medium">PREVIEW</span>
                    )}
                  </div>
                  <p className="text-[9px] text-muted-foreground truncate">{chatConfig?.assistantSubtitle || "Platform Support"}</p>
                </div>
              </div>

              <div className="flex items-center gap-0.5 flex-shrink-0">
                {/* Admin Persona Switcher */}
                {chatConfig?.canSwitchPersona && (
                  <div className="relative">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => setShowPersonaPicker(!showPersonaPicker)}
                      title="Switch persona"
                    >
                      <Users className="w-3.5 h-3.5" />
                    </Button>
                    {showPersonaPicker && (
                      <div className="absolute right-0 top-full mt-1 w-40 bg-popover text-popover-foreground border border-border rounded-md shadow-lg py-1 z-50">
                        <div className="px-2 py-1 text-[9px] text-muted-foreground uppercase tracking-wider border-b border-border mb-1">
                          Preview Persona
                        </div>
                        {chatConfig.availablePersonas.map((p) => (
                          <button
                            key={p}
                            onClick={() => {
                              setPersonaOverride(p === chatConfig.role && !chatConfig.isPersonaOverride ? undefined : p);
                              setShowPersonaPicker(false);
                            }}
                            className={cn(
                              "w-full text-left px-3 py-1.5 text-xs hover:bg-muted/50 transition-colors flex items-center gap-2",
                              role === p && "bg-primary/10 font-medium"
                            )}
                          >
                            <div className={cn("w-2 h-2 rounded-full", ROLE_ICON_COLORS[p]?.split(" ")[0] || "text-muted-foreground")} />
                            {ROLE_LABELS[p] || p}
                            {role === p && <CheckCircle2 className="w-3 h-3 ml-auto text-primary" />}
                          </button>
                        ))}
                        {personaOverride && (
                          <button
                            onClick={() => { setPersonaOverride(undefined); setShowPersonaPicker(false); }}
                            className="w-full text-left px-3 py-1.5 text-xs text-amber-500 hover:bg-muted/50 border-t border-border mt-1"
                          >
                            Reset to my role
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                )}
                <Button variant="ghost" size="icon" className="h-7 w-7" onClick={handleNewChat} title="New chat">
                  <Plus className="w-3.5 h-3.5" />
                </Button>
                <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setIsExpanded(!isExpanded)} title={isExpanded ? "Minimize" : "Expand"}>
                  {isExpanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
                </Button>
                <Button variant="ghost" size="icon" className="h-7 w-7 hover:bg-destructive/10 hover:text-destructive" onClick={() => { setIsOpen(false); setIsExpanded(false); setShowSidebar(false); setShowPersonaPicker(false); }} title="Close">
                  <X className="w-3.5 h-3.5" />
                </Button>
              </div>
            </div>

            {/* Context Toggles */}
            <div className="flex items-center gap-1.5 px-3 py-1.5 border-b border-border bg-muted/10 flex-shrink-0 flex-wrap">
              <span className="text-[9px] text-muted-foreground uppercase tracking-wider">Ctx:</span>
              {chatConfig?.canViewErrors && (
                <button
                  onClick={() => setIncludeErrors(!includeErrors)}
                  className={cn(
                    "flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium transition-colors",
                    includeErrors ? "bg-destructive/10 text-destructive border border-destructive/20" : "bg-muted text-muted-foreground border border-border hover:bg-muted/80"
                  )}
                >
                  <AlertTriangle className="w-2.5 h-2.5" /> Errors
                </button>
              )}
              {chatConfig?.canViewCreds && (
                <button
                  onClick={() => setIncludeCreds(!includeCreds)}
                  className={cn(
                    "flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium transition-colors",
                    includeCreds ? "bg-amber-500/10 text-amber-500 border border-amber-500/20" : "bg-muted text-muted-foreground border border-border hover:bg-muted/80"
                  )}
                >
                  <Key className="w-2.5 h-2.5" /> Creds
                </button>
              )}
              <button
                onClick={() => setIncludeKnowledgeBase(!includeKnowledgeBase)}
                className={cn(
                  "flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium transition-colors",
                  includeKnowledgeBase ? "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20" : "bg-muted text-muted-foreground border border-border hover:bg-muted/80"
                )}
              >
                <Zap className="w-2.5 h-2.5" /> Pentest KB
              </button>
              {chatConfig?.contextToggles?.map((toggle) => {
                const IconComp = ICON_MAP[toggle.icon] || Zap;
                return (
                  <button
                    key={toggle.key}
                    className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium bg-primary/10 text-primary border border-primary/20"
                  >
                    <IconComp className="w-2.5 h-2.5" /> {toggle.label}
                  </button>
                );
              })}
            </div>

            {/* Messages */}
            <div ref={scrollRef} className="flex-1 min-h-0 overflow-y-auto px-3 py-2">
              {messages.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full text-center py-8">
                  <div className={cn("w-10 h-10 rounded-full flex items-center justify-center mb-2", iconColor)}>
                    <Bot className="w-5 h-5" />
                  </div>
                  <p className="text-sm font-medium text-foreground/70">{chatConfig?.assistantName || "AI Assistant"}</p>
                  <p className="text-[10px] text-muted-foreground mt-1 max-w-[260px]">
                    {role === "operator" && "Attack planning, tool usage, OPSEC, and platform navigation."}
                    {role === "executive" && "Risk posture, compliance, and security strategy."}
                    {role === "analyst" && "Threat actors, IOCs, OSINT, and vulnerability analysis."}
                    {role === "team_lead" && "Engagements, team workload, and delivery planning."}
                    {role === "client" && "Assessment results, remediation, and security posture."}
                    {role === "admin" && "System health, configuration, and platform management."}
                  </p>

                  {/* Quick Actions */}
                  {chatConfig?.quickActions && chatConfig.quickActions.length > 0 && (
                    <div className="mt-3 w-full max-w-[300px]">
                      <p className="text-[9px] text-muted-foreground uppercase tracking-wider mb-1.5">Quick Actions</p>
                      <div className="grid grid-cols-2 gap-1">
                        {chatConfig.quickActions.slice(0, 4).map((action) => (
                          <button
                            key={action.name}
                            onClick={() => setInput(`${action.displayName}: `)}
                            className="text-[10px] px-2 py-1.5 rounded border border-border bg-muted/30 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors text-left flex items-center gap-1.5"
                          >
                            <Zap className="w-3 h-3 text-primary flex-shrink-0" />
                            <span className="truncate">{action.displayName}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Suggestions */}
                  <div className="flex flex-wrap gap-1 mt-3 justify-center">
                    {suggestions.slice(0, 4).map((suggestion) => (
                      <button
                        key={suggestion}
                        onClick={() => setInput(suggestion)}
                        className="text-[9px] px-2 py-1 rounded-full border border-border bg-muted/50 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                      >
                        {suggestion}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div className="space-y-3">
                {messages.map((msg, i) => (
                  <div key={i}>
                    {/* Tool/Action Result Card */}
                    {msg.role === "tool" && (
                      <div className="flex gap-2 justify-start">
                        <div className="w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 mt-1 bg-primary/10 text-primary">
                          <Zap className="w-2.5 h-2.5" />
                        </div>
                        <div className="max-w-[85%] rounded-lg border border-primary/20 bg-primary/5 px-3 py-2">
                          <div className="flex items-center gap-1.5 mb-1">
                            {msg.toolResult?.success ? (
                              <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                            ) : (
                              <XCircle className="w-3 h-3 text-destructive" />
                            )}
                            <span className="text-[10px] font-semibold text-foreground">{msg.toolName || "Action"}</span>
                          </div>
                          <p className="text-xs text-muted-foreground">{msg.content}</p>
                        </div>
                      </div>
                    )}

                    {/* User / Assistant Messages */}
                    {msg.role !== "tool" && (
                      <div className={cn("flex gap-2", msg.role === "user" ? "justify-end" : "justify-start")}>
                        {msg.role === "assistant" && (
                          <div className={cn("w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 mt-1", iconColor)}>
                            <Bot className="w-2.5 h-2.5" />
                          </div>
                        )}
                        <div
                          className={cn(
                            "max-w-[85%] rounded-lg px-3 py-2 text-sm",
                            msg.role === "user"
                              ? "bg-primary text-primary-foreground"
                              : "bg-muted/50 border border-border text-foreground"
                          )}
                        >
                          {msg.role === "assistant" ? (
                            <div className="prose prose-sm dark:prose-invert max-w-none [&_p]:my-1 [&_pre]:my-2 [&_ul]:my-1 [&_ol]:my-1">
                              <Streamdown>{msg.content}</Streamdown>
                            </div>
                          ) : (
                            <p className="whitespace-pre-wrap text-xs">{msg.content}</p>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                ))}

                {sendMutation.isPending && (
                  <div className="flex gap-2 justify-start">
                    <div className={cn("w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 mt-1", iconColor)}>
                      <Bot className="w-2.5 h-2.5" />
                    </div>
                    <div className="bg-muted/50 border border-border rounded-lg px-3 py-2">
                      <div className="flex items-center gap-2">
                        <Loader2 className="w-3 h-3 animate-spin text-muted-foreground" />
                        <span className="text-[10px] text-muted-foreground">Thinking...</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Input Area */}
            <div className="border-t border-border p-2.5 bg-muted/10 flex-shrink-0">
              <div className="flex gap-2">
                <Textarea
                  ref={inputRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder={chatConfig?.inputPlaceholder || "Ask anything..."}
                  className="min-h-[36px] max-h-[100px] resize-none text-xs"
                  rows={1}
                />
                <Button
                  size="icon"
                  onClick={handleSend}
                  disabled={!input.trim() || sendMutation.isPending}
                  className="h-9 w-9 flex-shrink-0"
                >
                  {sendMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                </Button>
              </div>
              <p className="text-[8px] text-muted-foreground mt-1 text-center">
                AI responses are advisory. Always verify within ROE scope.
                {activeSessionId && <span className="ml-1">\u00b7 Session #{activeSessionId}</span>}
              </p>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
