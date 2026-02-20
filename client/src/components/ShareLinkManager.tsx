import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import {
  Link2, Copy, Trash2, Plus, Eye, EyeOff, Clock, Shield,
  CheckCircle, XCircle, ExternalLink, Settings, Lock
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter
} from "@/components/ui/dialog";

interface ShareLinkManagerProps {
  engagementId: number;
}

export default function ShareLinkManager({ engagementId }: ShareLinkManagerProps) {
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newLabel, setNewLabel] = useState("Client Report");
  const [newPassword, setNewPassword] = useState("");
  const [newExpiresInDays, setNewExpiresInDays] = useState(30);
  const [newMaxViews, setNewMaxViews] = useState(0);
  const [newClientName, setNewClientName] = useState("");
  const [newBrandingColor, setNewBrandingColor] = useState("#14b8a6");
  const [newCustomMessage, setNewCustomMessage] = useState("");
  // Section toggles
  const [incSummary, setIncSummary] = useState(true);
  const [incFindings, setIncFindings] = useState(true);
  const [incAssets, setIncAssets] = useState(true);
  const [incRisk, setIncRisk] = useState(true);
  const [incRecs, setIncRecs] = useState(true);

  const utils = trpc.useUtils();

  const { data: shares, isLoading } = trpc.clientPortal.listShares.useQuery({ engagementId });

  const createShare = trpc.clientPortal.createShare.useMutation({
    onSuccess: () => {
      toast.success("Share link created successfully");
      utils.clientPortal.listShares.invalidate({ engagementId });
      setShowCreateDialog(false);
      resetForm();
    },
    onError: (err: any) => toast.error(sanitizeErrorForToast(err)),
  });

  const updateShare = trpc.clientPortal.updateShare.useMutation({
    onSuccess: () => {
      toast.success("Share link revoked");
      utils.clientPortal.listShares.invalidate({ engagementId });
    },
    onError: (err: any) => toast.error(sanitizeErrorForToast(err)),
  });

  function resetForm() {
    setNewLabel("Client Report");
    setNewPassword("");
    setNewExpiresInDays(30);
    setNewMaxViews(0);
    setNewClientName("");
    setNewBrandingColor("#14b8a6");
    setNewCustomMessage("");
    setIncSummary(true);
    setIncFindings(true);
    setIncAssets(true);
    setIncRisk(true);
    setIncRecs(true);
  }

  function handleCreate() {
    createShare.mutate({
      engagementId,
      accessPassword: newPassword || undefined,
      expiresInDays: newExpiresInDays || undefined,
      maxViews: newMaxViews || undefined,
      clientName: newClientName || undefined,
      brandingColor: newBrandingColor || undefined,
      customMessage: newCustomMessage || undefined,
      includeExecutiveSummary: incSummary,
      includeFindings: incFindings,
      includeAssets: incAssets,
      includeRiskScores: incRisk,
      includeRecommendations: incRecs,
    });
  }

  function copyLink(token: string) {
    const url = `${window.location.origin}/portal/${token}`;
    navigator.clipboard.writeText(url);
    toast.success("Share link copied to clipboard");
  }

  function openPortal(token: string) {
    window.open(`/portal/${token}`, "_blank");
  }

  const activeShares = useMemo(() => shares?.filter((s: any) => s.isActive) || [], [shares]);
  const revokedShares = useMemo(() => shares?.filter((s: any) => !s.isActive) || [], [shares]);

  return (
    <Card className="bg-slate-900/60 border-slate-700/50">
      <CardHeader className="flex flex-row items-center justify-between flex-wrap gap-2">
        <CardTitle className="text-lg text-white flex items-center gap-2">
          <Link2 className="w-5 h-5 text-teal-400" />
          Client Portal Links
        </CardTitle>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button size="sm" className="bg-teal-600 hover:bg-teal-700 text-white">
              <Plus className="w-4 h-4 mr-1.5" /> Create Share Link
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-slate-900 border-slate-700 max-w-lg max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="text-white">Create Client Share Link</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2">
              {/* Label */}
              <div>
                <Label className="text-slate-300 text-sm">Link Label</Label>
                <Input
                  value={newLabel}
                  onChange={(e) => setNewLabel(e.target.value)}
                  placeholder="e.g., Client Report - Q1 2026"
                  className="bg-slate-800 border-slate-600 text-white mt-1"
                />
              </div>

              {/* Client branding */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-slate-300 text-sm">Client Name</Label>
                  <Input
                    value={newClientName}
                    onChange={(e) => setNewClientName(e.target.value)}
                    placeholder="e.g., Acme Corp"
                    className="bg-slate-800 border-slate-600 text-white mt-1"
                  />
                </div>
                <div>
                  <Label className="text-slate-300 text-sm">Brand Color</Label>
                  <div className="flex gap-2 mt-1">
                    <input
                      type="color"
                      value={newBrandingColor}
                      onChange={(e) => setNewBrandingColor(e.target.value)}
                      className="w-10 h-10 rounded cursor-pointer bg-transparent border border-slate-600"
                    />
                    <Input
                      value={newBrandingColor}
                      onChange={(e) => setNewBrandingColor(e.target.value)}
                      className="bg-slate-800 border-slate-600 text-white flex-1"
                    />
                  </div>
                </div>
              </div>

              {/* Custom message */}
              <div>
                <Label className="text-slate-300 text-sm">Custom Message (optional)</Label>
                <Input
                  value={newCustomMessage}
                  onChange={(e) => setNewCustomMessage(e.target.value)}
                  placeholder="e.g., Please review the findings below and contact us with questions."
                  className="bg-slate-800 border-slate-600 text-white mt-1"
                />
              </div>

              {/* Security */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-slate-300 text-sm">Password (optional)</Label>
                  <Input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Leave empty for no password"
                    className="bg-slate-800 border-slate-600 text-white mt-1"
                  />
                </div>
                <div>
                  <Label className="text-slate-300 text-sm">Expires In (days)</Label>
                  <Input
                    type="number"
                    value={newExpiresInDays}
                    onChange={(e) => setNewExpiresInDays(parseInt(e.target.value) || 0)}
                    min={0}
                    placeholder="0 = never"
                    className="bg-slate-800 border-slate-600 text-white mt-1"
                  />
                </div>
              </div>

              <div>
                <Label className="text-slate-300 text-sm">Max Views (0 = unlimited)</Label>
                <Input
                  type="number"
                  value={newMaxViews}
                  onChange={(e) => setNewMaxViews(parseInt(e.target.value) || 0)}
                  min={0}
                  className="bg-slate-800 border-slate-600 text-white mt-1"
                />
              </div>

              {/* Section toggles */}
              <div className="space-y-3 pt-2 border-t border-slate-700/50">
                <p className="text-sm font-medium text-slate-300">Report Sections</p>
                <div className="space-y-2">
                  {[
                    { label: "Executive Summary", checked: incSummary, onChange: setIncSummary },
                    { label: "Findings", checked: incFindings, onChange: setIncFindings },
                    { label: "Assets", checked: incAssets, onChange: setIncAssets },
                    { label: "Risk Scores", checked: incRisk, onChange: setIncRisk },
                    { label: "Recommendations", checked: incRecs, onChange: setIncRecs },
                  ].map((s) => (
                    <div key={s.label} className="flex items-center justify-between">
                      <Label className="text-sm text-slate-400">{s.label}</Label>
                      <Switch checked={s.checked} onCheckedChange={s.onChange} />
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreateDialog(false)} className="border-slate-700 text-slate-300">
                Cancel
              </Button>
              <Button onClick={handleCreate} disabled={!newLabel || createShare.isPending} className="bg-teal-600 hover:bg-teal-700 text-white">
                {createShare.isPending ? "Creating..." : "Create Link"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading && (
          <div className="text-center py-6 text-slate-500">Loading share links...</div>
        )}

        {!isLoading && activeShares.length === 0 && revokedShares.length === 0 && (
          <div className="text-center py-8 text-slate-500">
            <Link2 className="w-10 h-10 mx-auto mb-3 opacity-40" />
            <p className="text-sm">No share links yet. Create one to share this engagement report with clients.</p>
          </div>
        )}

        {/* Active shares */}
        {activeShares.map((share: any) => (
          <div key={share.id} className="p-4 rounded-lg bg-slate-800/50 border border-slate-700/30 space-y-3">
            <div className="flex items-start justify-between gap-2 flex-wrap">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
                  <span className="font-medium text-white text-sm">{share.label}</span>
                  {share.passwordHash && (
                    <Badge variant="outline" className="text-xs border-amber-500/30 text-amber-400">
                      <Lock className="w-3 h-3 mr-1" /> Protected
                    </Badge>
                  )}
                </div>
                {share.clientName && (
                  <p className="text-xs text-slate-500 mt-0.5">For: {share.clientName}</p>
                )}
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <Button size="sm" variant="ghost" onClick={() => copyLink(share.token)} className="h-8 w-8 p-0 text-slate-400 hover:text-white">
                  <Copy className="w-4 h-4" />
                </Button>
                <Button size="sm" variant="ghost" onClick={() => openPortal(share.token)} className="h-8 w-8 p-0 text-slate-400 hover:text-white">
                  <ExternalLink className="w-4 h-4" />
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => updateShare.mutate({ id: share.id, isActive: false })}
                  className="h-8 w-8 p-0 text-slate-400 hover:text-red-400"
                  disabled={updateShare.isPending}
                >
                  <Trash2 className="w-4 h-4" />
                </Button>
              </div>
            </div>
            <div className="flex flex-wrap gap-3 text-xs text-slate-500">
              <span className="flex items-center gap-1">
                <Eye className="w-3.5 h-3.5" />
                {share.viewCount} views{share.maxViews ? ` / ${share.maxViews} max` : ""}
              </span>
              {share.expiresAt && (
                <span className="flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5" />
                  Expires {new Date(share.expiresAt).toLocaleDateString()}
                </span>
              )}
              <span className="flex items-center gap-1">
                <Settings className="w-3.5 h-3.5" />
                {[
                  share.includeExecutiveSummary && "Summary",
                  share.includeFindings && "Findings",
                  share.includeAssets && "Assets",
                  share.includeRiskScores && "Risk",
                  share.includeRecommendations && "Recs",
                ].filter(Boolean).join(", ")}
              </span>
            </div>
          </div>
        ))}

        {/* Revoked shares */}
        {revokedShares.length > 0 && (
          <div className="pt-3 border-t border-slate-700/30">
            <p className="text-xs text-slate-600 uppercase tracking-wider mb-2">Revoked Links</p>
            {revokedShares.map((share: any) => (
              <div key={share.id} className="p-3 rounded-lg bg-slate-800/20 border border-slate-800/30 opacity-50">
                <div className="flex items-center gap-2">
                  <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                  <span className="text-sm text-slate-500 line-through">{share.label}</span>
                  <span className="text-xs text-slate-600">
                    {share.viewCount} views • Revoked {new Date(share.updatedAt).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
