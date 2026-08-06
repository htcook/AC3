// @ts-nocheck
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Globe, Clock, Layers, Code, ChevronDown, ChevronUp,
  Fingerprint, Radio, Zap, Eye
} from "lucide-react";

const PROFILE_ICONS: Record<string, React.ReactNode> = {
  chrome_browser: <Globe className="w-4 h-4 text-blue-400" />,
  teams_api: <Layers className="w-4 h-4 text-purple-400" />,
  outlook_sync: <Layers className="w-4 h-4 text-cyan-400" />,
  slack_websocket: <Radio className="w-4 h-4 text-pink-400" />,
  windows_update: <Zap className="w-4 h-4 text-amber-400" />,
  cloudflare_api: <Globe className="w-4 h-4 text-orange-400" />,
};

const ENCODING_LABELS: Record<string, { label: string; color: string }> = {
  base64_in_json: { label: "Base64 in JSON", color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" },
  base64_in_cookie: { label: "Base64 in Cookie", color: "text-blue-400 bg-blue-500/10 border-blue-500/30" },
  steganographic: { label: "Steganographic", color: "text-purple-400 bg-purple-500/10 border-purple-500/30" },
  chunked_in_headers: { label: "Chunked in Headers", color: "text-amber-400 bg-amber-500/10 border-amber-500/30" },
};

interface TrafficProfilePreviewProps {
  selectedProfileId?: string;
  onProfileChange?: (profileId: string) => void;
  compact?: boolean;
}

export default function TrafficProfilePreview({
  selectedProfileId,
  onProfileChange,
  compact = false,
}: TrafficProfilePreviewProps) {
  const [expanded, setExpanded] = useState(false);
  const profilesQuery = trpc.ember.getTrafficProfiles.useQuery();
  const previewQuery = trpc.ember.getTrafficProfilePreview.useQuery(
    { profileId: selectedProfileId || "" },
    { enabled: !!selectedProfileId }
  );

  const profiles = profilesQuery.data || [];
  const preview = previewQuery.data;

  if (compact && !selectedProfileId) {
    return (
      <div className="space-y-2">
        <label className="text-sm font-medium flex items-center gap-2">
          <Fingerprint className="w-3.5 h-3.5 text-muted-foreground" />
          Traffic Profile
        </label>
        <Select value={selectedProfileId || ""} onValueChange={onProfileChange}>
          <SelectTrigger>
            <SelectValue placeholder="Select traffic profile..." />
          </SelectTrigger>
          <SelectContent>
            {profiles.map((p) => (
              <SelectItem key={p.id} value={p.id}>
                <span className="flex items-center gap-2">
                  {PROFILE_ICONS[p.id] || <Eye className="w-4 h-4" />}
                  {p.name}
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <label className="text-sm font-medium flex items-center gap-2">
          <Fingerprint className="w-3.5 h-3.5 text-muted-foreground" />
          Traffic Profile
        </label>
        <Select value={selectedProfileId || ""} onValueChange={onProfileChange}>
          <SelectTrigger className="w-[260px]">
            <SelectValue placeholder="Select traffic profile..." />
          </SelectTrigger>
          <SelectContent>
            {profiles.map((p) => (
              <SelectItem key={p.id} value={p.id}>
                <span className="flex items-center gap-2">
                  {PROFILE_ICONS[p.id] || <Eye className="w-4 h-4" />}
                  {p.name}
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Preview Card */}
      {preview && (
        <Card className="bg-zinc-900/60 border-border/40 overflow-hidden">
          <CardHeader className="py-3 px-4 cursor-pointer" onClick={() => setExpanded(!expanded)}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {PROFILE_ICONS[preview.id] || <Eye className="w-4 h-4" />}
                <div>
                  <CardTitle className="text-sm">{preview.name}</CardTitle>
                  <p className="text-xs text-muted-foreground mt-0.5">{preview.description}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline" className={ENCODING_LABELS[preview.payloadEncoding]?.color || ""}>
                  {ENCODING_LABELS[preview.payloadEncoding]?.label || preview.payloadEncoding}
                </Badge>
                {expanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </div>
            </div>

            {/* Quick stats row */}
            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                Beacon: {preview.beaconRange}
              </span>
              <span className="flex items-center gap-1">
                <Zap className="w-3 h-3" />
                {preview.burstInfo}
              </span>
            </div>
          </CardHeader>

          {expanded && (
            <CardContent className="px-4 pb-4 space-y-4 border-t border-border/30 pt-3">
              {/* HTTP Headers */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">HTTP Headers</h4>
                <div className="bg-zinc-950 rounded-lg border border-border/20 p-3 space-y-1 font-mono text-xs overflow-x-auto">
                  {Object.entries(preview.headers).map(([key, value]) => (
                    <div key={key} className="flex">
                      <span className="text-cyan-400 shrink-0">{key}:</span>
                      <span className="text-zinc-400 ml-2 break-all">{String(value)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* URL Patterns */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">URL Patterns</h4>
                <div className="flex flex-wrap gap-1.5">
                  {preview.urlPatterns.map((url: string) => (
                    <Badge key={url} variant="outline" className="font-mono text-[10px] bg-zinc-950/50">
                      {url}
                    </Badge>
                  ))}
                </div>
              </div>

              {/* Timing Details */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Timing Characteristics</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="bg-zinc-950/50 rounded-lg p-2.5 border border-border/20">
                    <p className="text-[10px] text-muted-foreground">Min Interval</p>
                    <p className="text-sm font-mono text-foreground">{(preview.timing.minIntervalMs / 1000).toFixed(1)}s</p>
                  </div>
                  <div className="bg-zinc-950/50 rounded-lg p-2.5 border border-border/20">
                    <p className="text-[10px] text-muted-foreground">Max Interval</p>
                    <p className="text-sm font-mono text-foreground">{(preview.timing.maxIntervalMs / 1000).toFixed(1)}s</p>
                  </div>
                  <div className="bg-zinc-950/50 rounded-lg p-2.5 border border-border/20">
                    <p className="text-[10px] text-muted-foreground">Burst Size</p>
                    <p className="text-sm font-mono text-foreground">{preview.timing.burstSize}</p>
                  </div>
                  <div className="bg-zinc-950/50 rounded-lg p-2.5 border border-border/20">
                    <p className="text-[10px] text-muted-foreground">Burst Interval</p>
                    <p className="text-sm font-mono text-foreground">{preview.timing.burstIntervalMs}ms</p>
                  </div>
                </div>
              </div>

              {/* Sample HTTP Request */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
                  <Code className="w-3 h-3" />
                  Sample HTTP Request
                </h4>
                <pre className="bg-zinc-950 rounded-lg border border-border/20 p-3 text-xs font-mono text-emerald-400/80 overflow-x-auto whitespace-pre-wrap max-h-48 overflow-y-auto">
                  {preview.sampleRequest}
                </pre>
              </div>

              {/* Response Content Types */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Expected Response Types</h4>
                <div className="flex flex-wrap gap-1.5">
                  {preview.responseContentTypes.map((ct: string) => (
                    <Badge key={ct} variant="outline" className="text-[10px] bg-zinc-950/50">
                      {ct}
                    </Badge>
                  ))}
                </div>
              </div>
            </CardContent>
          )}
        </Card>
      )}
    </div>
  );
}
