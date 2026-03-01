import { useState, useRef, useEffect, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Brain,
  Send,
  Zap,
  Shield,
  AlertTriangle,
  ChevronRight,
  Loader2,
  Sparkles,
  Target,
  MessageSquare,
  RefreshCw,
} from "lucide-react";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  timestamp: number;
}

export default function CampaignAdvisor() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [engagementId, setEngagementId] = useState<string>("");
  const [currentPhase, setCurrentPhase] = useState<string>("recon");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const chatMutation = trpc.campaignAdvisor.chat.useMutation();
  const quickMutation = trpc.campaignAdvisor.quickRecommend.useMutation();
  const { data: instantAdvice, refetch: refetchAdvice } = trpc.campaignAdvisor.instantAdvice.useQuery(
    { currentPhase, engagementId: engagementId || undefined },
  );
  const { data: engagementContext } = trpc.campaignAdvisor.getContext.useQuery(
    { engagementId: engagementId || undefined },
  );

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => { scrollToBottom(); }, [messages]);

  const phases = useMemo(() => [
    "pre_engagement", "recon", "scanning", "gaining_access",
    "maintaining_access", "escalation", "lateral_movement",
    "collection", "exfiltration", "reporting", "cleanup",
  ], []);

  const handleSend = async () => {
    if (!input.trim() || chatMutation.isPending) return;
    const userMsg: ChatMessage = { role: "user", content: input.trim(), timestamp: Date.now() };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");

    try {
      const result = await chatMutation.mutateAsync({
        messages: newMessages.map(m => ({ role: m.role, content: m.content })),
        engagementId: engagementId || undefined,
        context: { currentPhase },
      });
      setMessages(prev => [...prev, {
        role: "assistant",
        content: result.response,
        timestamp: Date.now(),
      }]);
    } catch (err) {
      setMessages(prev => [...prev, {
        role: "assistant",
        content: "I encountered an error processing your request. Please try again.",
        timestamp: Date.now(),
      }]);
    }
  };

  const handleQuickRecommend = async (question?: string) => {
    if (quickMutation.isPending) return;
    const userMsg: ChatMessage = {
      role: "user",
      content: question || "What should I do next?",
      timestamp: Date.now(),
    };
    setMessages(prev => [...prev, userMsg]);

    try {
      const result = await quickMutation.mutateAsync({
        engagementId: engagementId || undefined,
        question,
      });
      setMessages(prev => [...prev, {
        role: "assistant",
        content: result.response,
        timestamp: Date.now(),
      }]);
    } catch (err) {
      setMessages(prev => [...prev, {
        role: "assistant",
        content: "Unable to generate recommendation. Please try again.",
        timestamp: Date.now(),
      }]);
    }
  };

  const isLoading = chatMutation.isPending || quickMutation.isPending;

  const getRiskColor = (risk: number) => {
    if (risk <= 25) return "text-green-400";
    if (risk <= 50) return "text-yellow-400";
    if (risk <= 75) return "text-orange-400";
    return "text-red-400";
  };

  const getRiskBg = (risk: number) => {
    if (risk <= 25) return "bg-green-500/10 border-green-500/30";
    if (risk <= 50) return "bg-yellow-500/10 border-yellow-500/30";
    if (risk <= 75) return "bg-orange-500/10 border-orange-500/30";
    return "bg-red-500/10 border-red-500/30";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Brain className="h-7 w-7 text-violet-400" />
          Campaign Advisor
        </h1>
        <p className="text-muted-foreground mt-1">
          AI-powered tactical advisor that queries all five engines simultaneously to recommend the next best action based on your current engagement state, OPSEC exposure, and available attack paths.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Context & Quick Actions */}
        <div className="space-y-4">
          {/* Phase Selector */}
          <Card className="border-border/50 bg-card/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Engagement Context</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Current Phase</label>
                <Select value={currentPhase} onValueChange={(v) => { setCurrentPhase(v); refetchAdvice(); }}>
                  <SelectTrigger className="bg-background/50">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {phases.map(p => (
                      <SelectItem key={p} value={p}>
                        {p.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase())}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Engagement ID (optional)</label>
                <input
                  type="text"
                  value={engagementId}
                  onChange={e => setEngagementId(e.target.value)}
                  placeholder="e.g. eng_001"
                  className="w-full rounded-md border border-border/50 bg-background/50 px-3 py-2 text-sm"
                />
              </div>
              {engagementContext && (
                <div className="text-xs space-y-1">
                  {engagementContext.opsecScore !== undefined && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Avg OPSEC Score</span>
                      <span className={getRiskColor(engagementContext.opsecScore)}>
                        {engagementContext.opsecScore}/100
                      </span>
                    </div>
                  )}
                  {engagementContext.recentActions && engagementContext.recentActions.length > 0 && (
                    <div>
                      <span className="text-muted-foreground">Recent Actions: {engagementContext.recentActions.length}</span>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Instant Advice Card */}
          {instantAdvice && (
            <Card className={`border ${getRiskBg(instantAdvice.opsecRisk)}`}>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Zap className="h-4 w-4 text-amber-400" />
                  Instant Recommendation
                </CardTitle>
                <CardDescription className="text-xs">Deterministic advice — no LLM latency</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <p className="text-sm font-medium">{instantAdvice.nextAction}</p>
                  <p className="text-xs text-muted-foreground mt-1">{instantAdvice.reasoning}</p>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <Shield className="h-3 w-3" />
                  <span>OPSEC Risk: </span>
                  <span className={getRiskColor(instantAdvice.opsecRisk)}>{instantAdvice.opsecRisk}/100</span>
                  <Badge variant="outline" className="text-[10px] ml-auto">{instantAdvice.engine}</Badge>
                </div>
                <div className="space-y-1">
                  {instantAdvice.steps.slice(0, 3).map((step, i) => (
                    <div key={i} className="flex items-start gap-1.5 text-xs text-muted-foreground">
                      <ChevronRight className="h-3 w-3 mt-0.5 shrink-0" />
                      <span>{step}</span>
                    </div>
                  ))}
                  {instantAdvice.steps.length > 3 && (
                    <span className="text-[10px] text-muted-foreground">+{instantAdvice.steps.length - 3} more steps</span>
                  )}
                </div>
                {instantAdvice.warnings.length > 0 && (
                  <div className="space-y-1">
                    {instantAdvice.warnings.map((w, i) => (
                      <div key={i} className="flex items-start gap-1.5 text-xs text-amber-400">
                        <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
                        <span>{w}</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Quick Actions */}
          <Card className="border-border/50 bg-card/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-violet-400" />
                Quick Questions
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {[
                "What should I do next?",
                "What's my current OPSEC exposure?",
                "How do I escalate privileges on this Windows box?",
                "What lateral movement options do I have?",
                "Which CVE should I exploit first?",
                "How do I avoid EDR detection?",
              ].map((q, i) => (
                <Button
                  key={i}
                  variant="ghost"
                  size="sm"
                  className="w-full justify-start text-xs text-left h-auto py-2 px-3"
                  onClick={() => handleQuickRecommend(q)}
                  disabled={isLoading}
                >
                  <Target className="h-3 w-3 mr-2 shrink-0" />
                  {q}
                </Button>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Right: Chat Interface */}
        <div className="lg:col-span-2">
          <Card className="border-border/50 bg-card/50 flex flex-col" style={{ height: "calc(100vh - 200px)" }}>
            <CardHeader className="pb-3 border-b border-border/30 shrink-0">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <MessageSquare className="h-4 w-4" />
                  Advisor Chat
                </CardTitle>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setMessages([])}
                  className="text-xs"
                >
                  <RefreshCw className="h-3 w-3 mr-1" />
                  Clear
                </Button>
              </div>
            </CardHeader>

            {/* Messages Area */}
            <CardContent className="flex-1 overflow-y-auto p-4 space-y-4">
              {messages.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full text-center space-y-4">
                  <Brain className="h-16 w-16 text-violet-400/30" />
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Campaign Advisor Ready</p>
                    <p className="text-xs text-muted-foreground/70 mt-1 max-w-md">
                      Ask me anything about your engagement — I'll query all five engines
                      (Workflow, Lateral Movement, Exploitation, Privesc, OPSEC) to give you
                      the best tactical recommendation.
                    </p>
                  </div>
                </div>
              )}

              {messages.map((msg, i) => (
                <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                  <div className={`max-w-[85%] rounded-lg px-4 py-3 ${
                    msg.role === "user"
                      ? "bg-violet-600/20 border border-violet-500/30 text-sm"
                      : "bg-muted/30 border border-border/30 text-sm"
                  }`}>
                    {msg.role === "assistant" ? (
                      <div className="prose prose-invert prose-sm max-w-none [&_h1]:text-base [&_h2]:text-sm [&_h3]:text-sm [&_p]:text-sm [&_li]:text-sm [&_strong]:text-violet-300 [&_code]:text-amber-300 [&_code]:bg-black/30 [&_code]:px-1 [&_code]:rounded">
                        <div dangerouslySetInnerHTML={{
                          __html: msg.content
                            .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
                            .replace(/`(.*?)`/g, "<code>$1</code>")
                            .replace(/^### (.*$)/gm, "<h3>$1</h3>")
                            .replace(/^## (.*$)/gm, "<h2>$1</h2>")
                            .replace(/^# (.*$)/gm, "<h1>$1</h1>")
                            .replace(/^- (.*$)/gm, "<li>$1</li>")
                            .replace(/^(\d+)\. (.*$)/gm, "<li>$2</li>")
                            .replace(/\n\n/g, "</p><p>")
                            .replace(/\n/g, "<br/>")
                        }} />
                      </div>
                    ) : (
                      <p>{msg.content}</p>
                    )}
                    <p className="text-[10px] text-muted-foreground/50 mt-2">
                      {new Date(msg.timestamp).toLocaleTimeString()}
                    </p>
                  </div>
                </div>
              ))}

              {isLoading && (
                <div className="flex justify-start">
                  <div className="bg-muted/30 border border-border/30 rounded-lg px-4 py-3">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      <span>Querying all engines...</span>
                    </div>
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </CardContent>

            {/* Input Area */}
            <div className="p-4 border-t border-border/30 shrink-0">
              <div className="flex gap-2">
                <Textarea
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      handleSend();
                    }
                  }}
                  placeholder="Ask the Campaign Advisor anything..."
                  className="resize-none bg-background/50 min-h-[44px] max-h-[120px]"
                  rows={1}
                  disabled={isLoading}
                />
                <Button
                  onClick={handleSend}
                  disabled={!input.trim() || isLoading}
                  className="shrink-0 bg-violet-600 hover:bg-violet-700"
                >
                  {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                </Button>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
