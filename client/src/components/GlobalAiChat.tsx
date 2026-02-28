/**
 * Global AI Chat Widget — floating button + chat panel available on every page.
 * Provides contextual assistance with platform errors, OEM credentials, and engagement data.
 */
import { useState, useRef, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
// ScrollArea replaced with native overflow-y-auto div for reliable chat scrolling
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
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import { Streamdown } from "streamdown";
import { useLocation } from "wouter";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  timestamp: number;
}

export function GlobalAiChat() {
  const [isOpen, setIsOpen] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [includeErrors, setIncludeErrors] = useState(false);
  const [includeCreds, setIncludeCreds] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const [location] = useLocation();

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
            content: `⚠️ ${data.error}`,
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
          content: `⚠️ Connection error: ${err.message}. Please try again.`,
          timestamp: Date.now(),
        },
      ]);
    },
  });

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    if (scrollRef.current) {
      // Use requestAnimationFrame to ensure DOM has updated
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
  const hasUnread = messages.length > 0 && messages[messages.length - 1].role === "assistant" && !isOpen;

  return (
    <>
      {/* Floating Chat Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className={cn(
            "fixed bottom-6 right-6 z-[9999] w-14 h-14 rounded-full",
            "bg-primary text-primary-foreground shadow-lg",
            "flex items-center justify-center",
            "hover:scale-105 active:scale-95 transition-all duration-200",
            "border-2 border-primary/20",
            hasUnread && "animate-pulse ring-2 ring-primary/50"
          )}
          title="AI Assistant"
        >
          <MessageCircle className="w-6 h-6" />
          {hasUnread && (
            <span className="absolute -top-1 -right-1 w-4 h-4 bg-destructive rounded-full flex items-center justify-center">
              <span className="text-[10px] text-white font-bold">!</span>
            </span>
          )}
        </button>
      )}

      {/* Chat Panel */}
      {isOpen && (
        <div
          className={cn(
            "fixed z-[9999] bg-background border border-border rounded-lg shadow-2xl flex flex-col overflow-hidden transition-all duration-200",
            isExpanded
              ? "bottom-4 right-4 left-4 top-4 md:left-auto md:top-4 md:w-[600px]"
              : "bottom-6 right-6 w-[400px] h-[70vh] max-h-[700px] min-h-[400px]"
          )}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/30">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                <MessageCircle className="w-4 h-4 text-primary" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-foreground">
                  AI Assistant
                </h3>
                <p className="text-[10px] text-muted-foreground">
                  Caldera C2 Platform Support
                </p>
              </div>
            </div>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={clearChat}
                title="Clear chat"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={() => setIsExpanded(!isExpanded)}
                title={isExpanded ? "Minimize" : "Expand"}
              >
                {isExpanded ? (
                  <Minimize2 className="w-3.5 h-3.5" />
                ) : (
                  <Maximize2 className="w-3.5 h-3.5" />
                )}
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={() => setIsOpen(false)}
                title="Close"
              >
                <X className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>

          {/* Context Toggles */}
          <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-muted/10">
            <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
              Context:
            </span>
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
          </div>

          {/* Messages */}
          <div ref={scrollRef} className="flex-1 min-h-0 overflow-y-auto px-4 py-3">
            {messages.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-center py-12">
                <div className="w-12 h-12 rounded-full bg-primary/5 flex items-center justify-center mb-3">
                  <MessageCircle className="w-6 h-6 text-primary/40" />
                </div>
                <p className="text-sm font-medium text-foreground/70">
                  How can I help?
                </p>
                <p className="text-xs text-muted-foreground mt-1 max-w-[260px]">
                  Ask about attack planning, tool usage, platform errors, or
                  default credentials for discovered services.
                </p>
                <div className="flex flex-wrap gap-1.5 mt-4 justify-center">
                  {[
                    "What default creds for Cisco?",
                    "Help me plan an SSH brute-force",
                    "Review recent platform errors",
                    "How do I run a domain intel scan?",
                  ].map((suggestion) => (
                    <button
                      key={suggestion}
                      onClick={() => {
                        setInput(suggestion);
                        if (suggestion.toLowerCase().includes("cred")) setIncludeCreds(true);
                        if (suggestion.toLowerCase().includes("error")) setIncludeErrors(true);
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
                    <div className="w-6 h-6 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0 mt-1">
                      <MessageCircle className="w-3 h-3 text-primary" />
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
                  <div className="w-6 h-6 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0 mt-1">
                    <MessageCircle className="w-3 h-3 text-primary" />
                  </div>
                  <div className="bg-muted/50 border border-border rounded-lg px-3 py-2">
                    <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Input Area */}
          <div className="border-t border-border p-3 bg-muted/10">
            <div className="flex gap-2">
              <Textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about attacks, tools, errors, or credentials..."
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
