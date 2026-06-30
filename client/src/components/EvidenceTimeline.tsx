import { useMemo } from "react";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { formatKsiId } from "@/lib/ksi-labels";
import {
  CheckCircle2, XCircle, AlertTriangle, Clock, Hash,
  ArrowRight, Shield, ShieldAlert, FileCheck
} from "lucide-react";

interface EvidenceItem {
  evidenceId: string;
  ksiId: string;
  title: string;
  evidenceType: string;
  sourceModule: string;
  collectionMethod: string;
  status: string;
  integrityHash: string;
  previousHash?: string | null;
  createdAt?: string | number;
}

interface EvidenceTimelineProps {
  evidence: EvidenceItem[];
  maxItems?: number;
}

const STATUS_CONFIG: Record<string, { icon: typeof CheckCircle2; color: string; bgColor: string }> = {
  validated: { icon: CheckCircle2, color: "text-emerald-500", bgColor: "bg-emerald-500" },
  verified: { icon: Shield, color: "text-blue-500", bgColor: "bg-blue-500" },
  collected: { icon: FileCheck, color: "text-amber-500", bgColor: "bg-amber-500" },
  expired: { icon: Clock, color: "text-slate-400", bgColor: "bg-slate-400" },
  rejected: { icon: XCircle, color: "text-red-500", bgColor: "bg-red-500" },
};

export default function EvidenceTimeline({ evidence, maxItems = 20 }: EvidenceTimelineProps) {
  const items = useMemo(() => {
    return evidence.slice(0, maxItems);
  }, [evidence, maxItems]);

  if (items.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <ShieldAlert className="h-8 w-8 mx-auto mb-2 opacity-40" />
        <p className="text-sm">No evidence collected yet. Collect evidence to see the chain timeline.</p>
      </div>
    );
  }

  return (
    <TooltipProvider>
      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-5 top-0 bottom-0 w-px bg-border" />

        <div className="space-y-0">
          {items.map((ev, idx) => {
            const config = STATUS_CONFIG[ev.status] || STATUS_CONFIG.collected;
            const StatusIcon = config.icon;
            const hasChainLink = ev.previousHash && ev.previousHash.length > 0;
            const isFirst = idx === 0;

            return (
              <div key={ev.evidenceId} className="relative flex gap-4 py-3 group">
                {/* Timeline node */}
                <div className="relative z-10 flex-shrink-0">
                  <div className={`w-10 h-10 rounded-full border-2 flex items-center justify-center ${
                    ev.status === "validated" ? "border-emerald-500 bg-emerald-500/10" :
                    ev.status === "verified" ? "border-blue-500 bg-blue-500/10" :
                    ev.status === "rejected" ? "border-red-500 bg-red-500/10" :
                    "border-amber-500 bg-amber-500/10"
                  }`}>
                    <StatusIcon className={`h-4 w-4 ${config.color}`} />
                  </div>
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0 pb-1">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium">{ev.title}</span>
                        <Badge variant="outline" className="text-[10px] h-4 px-1" title={formatKsiId(ev.ksiId)}>
                          {ev.ksiId}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                        <span className="capitalize">{ev.evidenceType?.replace(/_/g, " ")}</span>
                        <span>·</span>
                        <span>{ev.sourceModule}</span>
                        <span>·</span>
                        <span className="capitalize">{ev.collectionMethod}</span>
                      </div>
                    </div>
                    <Badge variant={
                      ev.status === "validated" ? "default" :
                      ev.status === "verified" ? "secondary" :
                      ev.status === "rejected" ? "destructive" :
                      "outline"
                    } className="flex-shrink-0">
                      {ev.status}
                    </Badge>
                  </div>

                  {/* Hash chain visualization */}
                  <div className="mt-2 flex items-center gap-1.5 text-[10px] font-mono">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <div className="flex items-center gap-1 px-2 py-0.5 rounded bg-muted/50 cursor-default">
                          <Hash className="h-3 w-3 text-muted-foreground" />
                          <span className="text-muted-foreground">{ev.integrityHash?.slice(0, 16)}...</span>
                        </div>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p className="font-mono text-xs">SHA-256: {ev.integrityHash}</p>
                      </TooltipContent>
                    </Tooltip>

                    {hasChainLink && (
                      <>
                        <ArrowRight className="h-3 w-3 text-blue-400 flex-shrink-0" />
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <div className="flex items-center gap-1 px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 cursor-default">
                              <span className="text-blue-400">← {ev.previousHash?.slice(0, 12)}...</span>
                            </div>
                          </TooltipTrigger>
                          <TooltipContent>
                            <p className="font-mono text-xs">Previous hash: {ev.previousHash}</p>
                            <p className="text-xs mt-1">This evidence is cryptographically linked to the previous item in the chain</p>
                          </TooltipContent>
                        </Tooltip>
                      </>
                    )}

                    {isFirst && !hasChainLink && (
                      <span className="text-emerald-400 text-[10px]">← Genesis block</span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {evidence.length > maxItems && (
          <div className="text-center text-xs text-muted-foreground mt-2 pt-2 border-t">
            Showing {maxItems} of {evidence.length} evidence items
          </div>
        )}
      </div>
    </TooltipProvider>
  );
}
