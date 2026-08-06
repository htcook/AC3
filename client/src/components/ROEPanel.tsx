/**
 * ROE (Rules of Engagement) Management Panel
 *
 * Displays ROE status for an engagement and provides:
 * - PDF document upload
 * - Start / expiry date pickers
 * - Signer name & email
 * - Scope definition (domains, IP ranges, exclusions)
 * - Status transitions (none → pending → signed → expired)
 */
import { useState, useRef, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Upload,
  FileText,
  Calendar,
  User,
  Mail,
  Globe,
  Network,
  Ban,
  ExternalLink,
  Loader2,
  CheckCircle,
  Clock,
  AlertTriangle,
} from "lucide-react";

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: React.ReactNode; description: string }> = {
  none: {
    label: "NO ROE",
    color: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    icon: <ShieldX className="w-4 h-4" />,
    description: "No Rules of Engagement have been uploaded. Offensive operations (phishing, exploitation, emulation) are blocked.",
  },
  pending: {
    label: "PENDING",
    color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    icon: <Clock className="w-4 h-4" />,
    description: "ROE document uploaded but awaiting signature/approval. Offensive operations remain blocked until status is set to 'Signed'.",
  },
  signed: {
    label: "ACTIVE",
    color: "bg-green-500/20 text-green-400 border-green-500/30",
    icon: <ShieldCheck className="w-4 h-4" />,
    description: "ROE is signed and active. All offensive operations within scope are authorized.",
  },
  expired: {
    label: "EXPIRED",
    color: "bg-red-500/20 text-red-400 border-red-500/30",
    icon: <ShieldAlert className="w-4 h-4" />,
    description: "ROE has expired. Offensive operations are blocked. Upload a new ROE or extend the expiry date.",
  },
};

interface ROEPanelProps {
  engagementId: number;
  engagementName: string;
  targetDomain?: string;
}

export default function ROEPanel({ engagementId, engagementName, targetDomain }: ROEPanelProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [saving, setSaving] = useState(false);

  // Fetch current ROE status
  const { data: roe, refetch, isLoading } = trpc.roeAudit.getROEStatus.useQuery(
    { engagementId },
  );

  // Form state — initialized from server data
  const [formState, setFormState] = useState<{
    roeStatus: string;
    roeSignedDate: string;
    roeExpiryDate: string;
    roeSignerName: string;
    roeSignerEmail: string;
    scopeDomains: string;
    scopeIpRanges: string;
    scopeExcluded: string;
    scopeRestrictions: string;
  } | null>(null);

  // Initialize form from fetched data
  const form = formState ?? {
    roeStatus: roe?.roeStatus ?? "none",
    roeSignedDate: roe?.roeSignedDate ? new Date(roe.roeSignedDate).toISOString().split("T")[0] : "",
    roeExpiryDate: roe?.roeExpiryDate ? new Date(roe.roeExpiryDate).toISOString().split("T")[0] : "",
    roeSignerName: roe?.roeSignerName ?? "",
    roeSignerEmail: roe?.roeSignerEmail ?? "",
    scopeDomains: (roe?.roeScope as any)?.domains?.join(", ") ?? targetDomain ?? "",
    scopeIpRanges: (roe?.roeScope as any)?.ipRanges?.join(", ") ?? "",
    scopeExcluded: (roe?.roeScope as any)?.excludedTargets?.join(", ") ?? "",
    scopeRestrictions: (roe?.roeScope as any)?.restrictions ?? "",
  };

  const setField = (key: string, value: string) => {
    setFormState(prev => ({
      ...(prev ?? form),
      [key]: value,
    }));
  };

  // Mutations
  const updateROE = trpc.roeAudit.updateROE.useMutation({
    onSuccess: () => {
      toast.success("ROE updated successfully");
      setSaving(false);
      setFormState(null);
      refetch();
    },
    onError: (err) => {
      toast.error(`Failed to update ROE: ${err.message}`);
      setSaving(false);
    },
  });

  const uploadDoc = trpc.roeAudit.uploadROEDocument.useMutation({
    onSuccess: (data) => {
      toast.success(`ROE document uploaded (${(data.fileSize / 1024).toFixed(1)} KB)`);
      setUploading(false);
      refetch();
    },
    onError: (err) => {
      toast.error(`Upload failed: ${err.message}`);
      setUploading(false);
    },
  });

  const handleFileSelect = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 20 * 1024 * 1024) {
      toast.error("File must be under 20 MB");
      return;
    }

    if (!file.type.includes("pdf") && !file.name.endsWith(".pdf")) {
      toast.error("Only PDF files are accepted");
      return;
    }

    setUploading(true);
    try {
      const arrayBuffer = await file.arrayBuffer();
      const base64 = btoa(
        new Uint8Array(arrayBuffer).reduce((data, byte) => data + String.fromCharCode(byte), "")
      );
      uploadDoc.mutate({
        engagementId,
        fileName: file.name,
        fileData: base64,
        mimeType: file.type || "application/pdf",
      });
    } catch (err) {
      toast.error("Failed to read file");
      setUploading(false);
    }

    // Reset input so the same file can be re-selected
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, [engagementId, uploadDoc]);

  const handleSave = () => {
    setSaving(true);
    const scopeDomains = form.scopeDomains.split(",").map((s: string) => s.trim()).filter(Boolean);
    const scopeIpRanges = form.scopeIpRanges.split(",").map((s: string) => s.trim()).filter(Boolean);
    const scopeExcluded = form.scopeExcluded.split(",").map((s: string) => s.trim()).filter(Boolean);

    updateROE.mutate({
      engagementId,
      roeStatus: form.roeStatus as any,
      roeSignedDate: form.roeSignedDate || undefined,
      roeExpiryDate: form.roeExpiryDate || undefined,
      roeSignerName: form.roeSignerName || undefined,
      roeSignerEmail: form.roeSignerEmail || undefined,
      roeScope: {
        domains: scopeDomains.length > 0 ? scopeDomains : undefined,
        ipRanges: scopeIpRanges.length > 0 ? scopeIpRanges : undefined,
        excludedTargets: scopeExcluded.length > 0 ? scopeExcluded : undefined,
        restrictions: form.scopeRestrictions || undefined,
      },
    });
  };

  if (isLoading) {
    return (
      <div className="border border-border bg-card p-6 mt-4">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Loader2 className="w-4 h-4 animate-spin" />
          <span className="text-xs font-display tracking-wider">LOADING ROE STATUS...</span>
        </div>
      </div>
    );
  }

  const statusConfig = STATUS_CONFIG[roe?.roeStatus ?? "none"] ?? STATUS_CONFIG.none;

  return (
    <div className="border border-border bg-card mt-4">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-border">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-primary" />
          <h3 className="font-display text-sm tracking-wider">RULES OF ENGAGEMENT</h3>
          <Badge variant="outline" className={statusConfig.color}>
            <span className="flex items-center gap-1">
              {statusConfig.icon}
              {statusConfig.label}
            </span>
          </Badge>
        </div>
      </div>

      {/* Status Description */}
      <div className={`px-4 py-3 text-xs border-b border-border ${
        roe?.roeStatus === "signed" ? "bg-green-500/5 text-green-400" :
        roe?.roeStatus === "expired" ? "bg-red-500/5 text-red-400" :
        roe?.roeStatus === "pending" ? "bg-yellow-500/5 text-yellow-400" :
        "bg-gray-500/5 text-gray-400"
      }`}>
        <div className="flex items-start gap-2">
          {roe?.roeStatus === "none" || !roe?.roeStatus ? (
            <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          ) : roe?.roeStatus === "signed" ? (
            <CheckCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          ) : (
            <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          )}
          <span>{statusConfig.description}</span>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Document Upload */}
        <div>
          <Label className="text-xs font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5" /> SIGNED ROE DOCUMENT
          </Label>
          <div className="flex items-center gap-3">
            <input
              ref={fileInputRef}
              type="file"
              accept=".pdf,application/pdf"
              onChange={handleFileSelect}
              className="hidden"
            />
            <Button
              variant="outline"
              size="sm"
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              className="font-display tracking-wider text-xs"
            >
              {uploading ? (
                <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
              ) : (
                <Upload className="w-3.5 h-3.5 mr-1.5" />
              )}
              {uploading ? "UPLOADING..." : "UPLOAD PDF"}
            </Button>
            {roe?.roeDocumentUrl && (
              <a
                href={roe.roeDocumentUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-xs text-primary hover:text-primary/80 font-display tracking-wider"
              >
                <ExternalLink className="w-3 h-3" />
                VIEW DOCUMENT
              </a>
            )}
            {!roe?.roeDocumentUrl && !uploading && (
              <span className="text-xs text-muted-foreground">No document uploaded</span>
            )}
          </div>
        </div>

        {/* ROE Status Selector */}
        <div>
          <Label className="text-xs font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5" /> ROE STATUS
          </Label>
          <div className="flex gap-2 flex-wrap">
            {(["none", "pending", "signed", "expired"] as const).map(status => {
              const cfg = STATUS_CONFIG[status];
              const isActive = form.roeStatus === status;
              return (
                <button
                  key={status}
                  onClick={() => setField("roeStatus", status)}
                  className={`px-3 py-1.5 text-xs font-display tracking-wider border transition-colors ${
                    isActive
                      ? cfg.color + " border-current"
                      : "border-border text-muted-foreground hover:border-primary/30"
                  }`}
                >
                  <span className="flex items-center gap-1">
                    {cfg.icon}
                    {cfg.label}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Dates Row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <Label className="text-xs font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <Calendar className="w-3.5 h-3.5" /> ROE SIGNED DATE
            </Label>
            <Input
              type="date"
              value={form.roeSignedDate}
              onChange={(e) => setField("roeSignedDate", e.target.value)}
              className="bg-background border-border text-sm"
            />
          </div>
          <div>
            <Label className="text-xs font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <Calendar className="w-3.5 h-3.5" /> ROE EXPIRY DATE
            </Label>
            <Input
              type="date"
              value={form.roeExpiryDate}
              onChange={(e) => setField("roeExpiryDate", e.target.value)}
              className="bg-background border-border text-sm"
            />
          </div>
        </div>

        {/* Signer Info */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <Label className="text-xs font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <User className="w-3.5 h-3.5" /> SIGNER NAME
            </Label>
            <Input
              placeholder="e.g. Jane Smith, CISO"
              value={form.roeSignerName}
              onChange={(e) => setField("roeSignerName", e.target.value)}
              className="bg-background border-border text-sm"
            />
          </div>
          <div>
            <Label className="text-xs font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <Mail className="w-3.5 h-3.5" /> SIGNER EMAIL
            </Label>
            <Input
              type="email"
              placeholder="e.g. ciso@client.com"
              value={form.roeSignerEmail}
              onChange={(e) => setField("roeSignerEmail", e.target.value)}
              className="bg-background border-border text-sm"
            />
          </div>
        </div>

        {/* Scope */}
        <div className="space-y-3">
          <h4 className="text-xs font-display tracking-wider text-muted-foreground flex items-center gap-1.5">
            <Globe className="w-3.5 h-3.5" /> AUTHORIZED SCOPE
          </h4>
          <div>
            <Label className="text-xs text-muted-foreground mb-1 block">Target Domains (comma-separated)</Label>
            <Input
              placeholder="e.g. example.com, *.example.com"
              value={form.scopeDomains}
              onChange={(e) => setField("scopeDomains", e.target.value)}
              className="bg-background border-border text-sm"
            />
          </div>
          <div>
            <Label className="text-xs text-muted-foreground mb-1 block">IP Ranges (comma-separated CIDR)</Label>
            <Input
              placeholder="e.g. 10.0.0.0/24, 192.168.1.0/24"
              value={form.scopeIpRanges}
              onChange={(e) => setField("scopeIpRanges", e.target.value)}
              className="bg-background border-border text-sm"
            />
          </div>
          <div>
            <Label className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
              <Ban className="w-3 h-3" /> Excluded Targets (comma-separated)
            </Label>
            <Input
              placeholder="e.g. production-db.example.com, 10.0.0.1"
              value={form.scopeExcluded}
              onChange={(e) => setField("scopeExcluded", e.target.value)}
              className="bg-background border-border text-sm"
            />
          </div>
          <div>
            <Label className="text-xs text-muted-foreground mb-1 block">Additional Restrictions</Label>
            <Textarea
              placeholder="e.g. No denial-of-service testing. Testing window: Mon-Fri 9am-5pm EST only."
              value={form.scopeRestrictions}
              onChange={(e) => setField("scopeRestrictions", e.target.value)}
              className="bg-background border-border text-sm min-h-[60px]"
            />
          </div>
        </div>

        {/* Save Button */}
        <div className="flex items-center justify-between pt-2 border-t border-border">
          <p className="text-xs text-muted-foreground">
            Changes are saved to the engagement record and enforced across all offensive operations.
          </p>
          <Button
            onClick={handleSave}
            disabled={saving}
            className="font-display tracking-wider"
            size="sm"
          >
            {saving ? (
              <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
            ) : (
              <ShieldCheck className="w-3.5 h-3.5 mr-1.5" />
            )}
            {saving ? "SAVING..." : "SAVE ROE"}
          </Button>
        </div>
      </div>
    </div>
  );
}
