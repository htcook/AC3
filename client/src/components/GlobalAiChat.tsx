/**
 * Global AI Chat Widget — role-specialized floating chat panel.
 *
 * Fetches role-specific configuration from the backend (assistant name,
 * suggestions, context toggles) so each user role gets a tailored AI persona.
 *
 * Button positioned top-right to avoid overlapping sidebar navigation.
 * Close / minimize buttons are always rendered (never conditionally hidden).
 */
import { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import {
  MessageCircle,
  X,
  Send,
  Loader2,
  AlertTriangle,
  Key,
  Minimize2,
  Maximize2,
  Trash2,
  Shield,
  Target,
  Eye,
  Globe,
  Users,
  BarChart3,
  FileText,
  Cpu,
  Zap,
  Bot,
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import { Streamdown } from "streamdown";
import { useLocation } from "wouter";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  timestamp: number;
}

/** Map icon name strings from backend to Lucide components */
const ICON_MAP: Record<string, React.ComponentType<{ className?: string }>> = {
  Shield, Target, Eye, Globe, Users, BarChart3, FileText, Cpu, AlertTriangle, Key,
};

/** Role-specific accent colors for the chat header */
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

export function GlobalAiChat() {
  const [isOpen, setIsOpen] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [includeErrors, setIncludeErrors] = useState(false);
  const [includeCreds, setIncludeCreds] = useState(false);
  const [extraToggles, setExtraToggles] = useState<Record<string, boolean>>({});
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const [location] = useLocation();

  // Fetch role-specific chat configuration from backend
  const { data: chatConfig } = trpc.aiChat.getConfig.useQuery(undefined, {
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: 60_000,
  });

  const role = chatConfig?.role || "operator";
  const accent = ROLE_ACCENTS[role] || ROLE_ACCENTS.operator;
  const iconColor = ROLE_ICON_COLORS[role] || ROLE_ICON_COLORS.operator;

  const sendMutation = trpc.aiChat.send.useMutation({
    onSuccess: (data) => {
      if (data.reply) {
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: data.reply!, timestamp: Date.now() },
        ]);
      } else if (data.error) {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: `\u26a0\ufe0f ${data.error}`,
            timestamp: Date.now(),
          },
        ]);
      }
    },
    onError: (err) => {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `\u26a0\ufe0f Connection error: ${err.message}. Please try again.`,
          timestamp: Date.now(),
        },
      ]);
    },
  });

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    if (scrollRef.current) {
      requestAnimationFrame(() => {
        scrollRef.current!.scrollTop = scrollRef.current!.scrollHeight;
      });
    }
  }, [messages, sendMutation.isPending]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [isOpen]);

  const handleSend = useCallback(() => {
    const trimmed = input.trim();
    if (!trimmed || sendMutation.isPending) return;

    const newMsg: ChatMessage = {
      role: "user",
      content: trimmed,
      timestamp: Date.now(),
    };
    setMessages((prev) => [...prev, newMsg]);
    setInput("");

    sendMutation.mutate({
      message: trimmed,
      conversationHistory: messages.slice(-20).map((m) => ({
        role: m.role,
        content: m.content,
      })),
      currentPage: location,
      includeErrors,
      includeCreds,
      includeRoleContext: true,
    });
  }, [input, messages, location, includeErrors, includeCreds, sendMutation]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const clearChat = () => {
    setMessages([]);
  };

  // Unread indicator
  const hasUnread =
    messages.length > 0 &&
    messages[messages.length - 1].role === "assistant" &&
    !isOpen;

  const suggestions = useMemo(
    () => chatConfig?.suggestions || [
      "How can you help me?",
      "What's the current status?",
    ],
    [chatConfig?.suggestions]
  );

  return (
    <>
      {/* ── Floating Chat Button — top-right, clear of sidebar ── */}
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
            "fixed z-[9999] bg-background border border-border rounded-lg shadow-2xl flex flex-col overflow-hidden transition-all duration-200",
            isExpanded
              ? "top-4 right-4 bottom-4 left-4 md:left-auto md:w-[600px]"
              : "top-4 right-4 w-[400px] h-[70vh] max-h-[700px] min-h-[400px]"
          )}
        >
          {/* ── Header — role-specific styling ── */}
          <div
            className={cn(
              "flex items-center justify-between px-4 py-3 border-b flex-shrink-0 bg-gradient-to-r",
              accent
            )}
          >
            <div className="flex items-center gap-2 min-w-0">
              <div
                className={cn(
                  "w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0",
                  iconColor
                )}
              >
                <Bot className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <h3 className="text-sm font-semibold text-foreground truncate">
                  {chatConfig?.assistantName || "AI Assistant"}
                </h3>
                <p className="text-[10px] text-muted-foreground truncate">
                  {chatConfig?.assistantSubtitle || "Platform Support"}
                </p>
              </div>
            </div>

            {/* Action buttons — always visible */}
            <div className="flex items-center gap-1 flex-shrink-0">
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 hover:bg-destructive/10 hover:text-destructive"
                onClick={clearChat}
                title="Clear chat"
              >
                <Trash2 className="w-4 h-4" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={() => setIsExpanded(!isExpanded)}
                title={isExpanded ? "Minimize" : "Expand"}
              >
                {isExpanded ? (
                  <Minimize2 className="w-4 h-4" />
                ) : (
                  <Maximize2 className="w-4 h-4" />
                )}
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 hover:bg-destructive/10 hover:text-destructive"
                onClick={() => {
                  setIsOpen(false);
                  setIsExpanded(false);
                }}
                title="Close chat"
              >
                <X className="w-4 h-4" />
              </Button>
            </div>
          </div>

          {/* Context Toggles — role-aware */}
          <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-muted/10 flex-shrink-0 flex-wrap">
            <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
              Context:
            </span>
            {chatConfig?.canViewErrors && (
              <button
                onClick={() => setIncludeErrors(!includeErrors)}
                className={cn(
                  "flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium transition-colors",
                  includeErrors
                    ? "bg-destructive/10 text-destructive border border-destructive/20"
                    : "bg-muted text-muted-foreground border border-border hover:bg-muted/80"
                )}
              >
                <AlertTriangle className="w-3 h-3" />
                Errors
              </button>
            )}
            {chatConfig?.canViewCreds && (
              <button
                onClick={() => setIncludeCreds(!includeCreds)}
                className={cn(
                  "flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium transition-colors",
                  includeCreds
                    ? "bg-amber-500/10 text-amber-500 border border-amber-500/20"
                    : "bg-muted text-muted-foreground border border-border hover:bg-muted/80"
                )}
              >
                <Key className="w-3 h-3" />
                Default Creds
              </button>
            )}
            {/* Role-specific extra context toggles */}
            {chatConfig?.contextToggles?.map((toggle) => {
              const IconComp = ICON_MAP[toggle.icon] || Zap;
              const isActive = extraToggles[toggle.key] || false;
              return (
                <button
                  key={toggle.key}
                  onClick={() =>
                    setExtraToggles((prev) => ({
                      ...prev,
                      [toggle.key]: !prev[toggle.key],
                    }))
                  }
                  className={cn(
                    "flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium transition-colors",
                    isActive
                      ? "bg-primary/10 text-primary border border-primary/20"
                      : "bg-muted text-muted-foreground border border-border hover:bg-muted/80"
                  )}
                >
                  <IconComp className="w-3 h-3" />
                  {toggle.label}
                </button>
              );
            })}
          </div>

          {/* Messages */}
          <div
            ref={scrollRef}
            className="flex-1 min-h-0 overflow-y-auto px-4 py-3"
          >
            {messages.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-center py-12">
                <div
                  className={cn(
                    "w-12 h-12 rounded-full flex items-center justify-center mb-3",
                    iconColor
                  )}
                >
                  <Bot className="w-6 h-6" />
                </div>
                <p className="text-sm font-medium text-foreground/70">
                  {chatConfig?.assistantName || "AI Assistant"}
                </p>
                <p className="text-xs text-muted-foreground mt-1 max-w-[280px]">
                  {role === "operator" && "Ask about attack planning, tool usage, OPSEC, or platform navigation."}
                  {role === "executive" && "Ask about risk posture, compliance status, or security strategy."}
                  {role === "analyst" && "Ask about threat actors, IOCs, OSINT, or vulnerability analysis."}
                  {role === "team_lead" && "Ask about engagements, team workload, or delivery planning."}
                  {role === "client" && "Ask about your assessment results, remediation, or security posture."}
                  {role === "admin" && "Ask about system health, configuration, or platform management."}
                  {!["operator", "executive", "analyst", "team_lead", "client", "admin"].includes(role) &&
                    "How can I help you today?"}
                </p>
                <div className="flex flex-wrap gap-1.5 mt-4 justify-center">
                  {suggestions.map((suggestion) => (
                    <button
                      key={suggestion}
                      onClick={() => {
                        setInput(suggestion);
                        if (suggestion.toLowerCase().includes("cred"))
                          setIncludeCreds(true);
                        if (suggestion.toLowerCase().includes("error"))
                          setIncludeErrors(true);
                      }}
                      className="text-[10px] px-2.5 py-1 rounded-full border border-border bg-muted/50 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-4">
              {messages.map((msg, i) => (
                <div
                  key={i}
                  className={cn(
                    "flex gap-2",
                    msg.role === "user" ? "justify-end" : "justify-start"
                  )}
                >
                  {msg.role === "assistant" && (
                    <div
                      className={cn(
                        "w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 mt-1",
                        iconColor
                      )}
                    >
                      <Bot className="w-3 h-3" />
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
                      <p className="whitespace-pre-wrap">{msg.content}</p>
                    )}
                  </div>
                </div>
              ))}

              {sendMutation.isPending && (
                <div className="flex gap-2 justify-start">
                  <div
                    className={cn(
                      "w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 mt-1",
                      iconColor
                    )}
                  >
                    <Bot className="w-3 h-3" />
                  </div>
                  <div className="bg-muted/50 border border-border rounded-lg px-3 py-2">
                    <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Input Area */}
          <div className="border-t border-border p-3 bg-muted/10 flex-shrink-0">
            <div className="flex gap-2">
              <Textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder={
                  chatConfig?.inputPlaceholder ||
                  "Ask about attacks, tools, errors, or credentials..."
                }
                className="min-h-[40px] max-h-[120px] resize-none text-sm"
                rows={1}
              />
              <Button
                size="icon"
                onClick={handleSend}
                disabled={!input.trim() || sendMutation.isPending}
                className="h-10 w-10 flex-shrink-0"
              >
                {sendMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
                )}
              </Button>
            </div>
            <p className="text-[9px] text-muted-foreground mt-1.5 text-center">
              AI responses are advisory. Always verify within ROE scope.
            </p>
          </div>
        </div>
      )}
    </>
  );
}
