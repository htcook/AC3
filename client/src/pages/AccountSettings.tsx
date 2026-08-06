import { useState } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  UserCog,
  Shield,
  ShieldCheck,
  Clock,
  Mail,
  Phone,
  Building,
  Globe,
  Save,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Fingerprint,
  Key,
  KeyRound,
  QrCode,
  Copy,
  Eye,
  EyeOff,
  Smartphone,
  Monitor,
  Trash2,
  ShieldOff,
  RefreshCw,
} from "lucide-react";

const TIMEZONES = [
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "America/Anchorage",
  "Pacific/Honolulu",
  "UTC",
  "Europe/London",
  "Europe/Berlin",
  "Asia/Tokyo",
  "Asia/Shanghai",
  "Australia/Sydney",
];

const ROLE_LABELS: Record<string, string> = {
  admin: "Administrator",
  operator: "Operator",
  analyst: "Analyst",
  team_lead: "Team Lead",
  executive: "Executive",
  client: "Client",
  user: "User",
  viewer: "Viewer",
};

function PasswordChangeForm() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPasswords, setShowPasswords] = useState(false);

  const changePassword = trpc.accountAuth.changePassword.useMutation({
    onSuccess: () => {
      toast.success("Password changed successfully");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    },
    onError: (err) => toast.error(err.message),
  });

  const passwordValid = newPassword.length >= 12
    && /[A-Z]/.test(newPassword)
    && /[a-z]/.test(newPassword)
    && /[0-9]/.test(newPassword)
    && /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPassword);
  const passwordsMatch = newPassword === confirmPassword && confirmPassword.length > 0;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!passwordValid) {
      toast.error("Password does not meet NIST SP 800-63B requirements");
      return;
    }
    if (!passwordsMatch) {
      toast.error("Passwords do not match");
      return;
    }
    changePassword.mutate({ currentPassword, newPassword });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="currentPassword">Current Password</Label>
        <Input
          id="currentPassword"
          type={showPasswords ? "text" : "password"}
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
          placeholder="Enter current password"
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="newPassword">New Password</Label>
        <Input
          id="newPassword"
          type={showPasswords ? "text" : "password"}
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          placeholder="Min 12 chars, upper+lower+number+special"
          required
        />
        {newPassword.length > 0 && (
          <div className="grid grid-cols-2 gap-1 text-xs mt-1">
            <span className={newPassword.length >= 12 ? "text-green-500" : "text-red-400"}>✓ 12+ characters</span>
            <span className={/[A-Z]/.test(newPassword) ? "text-green-500" : "text-red-400"}>✓ Uppercase letter</span>
            <span className={/[a-z]/.test(newPassword) ? "text-green-500" : "text-red-400"}>✓ Lowercase letter</span>
            <span className={/[0-9]/.test(newPassword) ? "text-green-500" : "text-red-400"}>✓ Number</span>
            <span className={/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPassword) ? "text-green-500" : "text-red-400"}>✓ Special character</span>
          </div>
        )}
      </div>
      <div className="space-y-2">
        <Label htmlFor="confirmPassword">Confirm New Password</Label>
        <Input
          id="confirmPassword"
          type={showPasswords ? "text" : "password"}
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          placeholder="Re-enter new password"
          required
        />
        {confirmPassword.length > 0 && !passwordsMatch && (
          <p className="text-xs text-red-400">Passwords do not match</p>
        )}
      </div>
      <div className="flex items-center gap-4 pt-2">
        <Button
          type="submit"
          disabled={!passwordValid || !passwordsMatch || !currentPassword || changePassword.isPending}
        >
          {changePassword.isPending ? (
            <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> CHANGING...</>
          ) : (
            <><Lock className="w-4 h-4 mr-2" /> CHANGE PASSWORD</>
          )}
        </Button>
        <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
          <input
            type="checkbox"
            checked={showPasswords}
            onChange={(e) => setShowPasswords(e.target.checked)}
            className="rounded"
          />
          Show passwords
        </label>
      </div>
    </form>
  );
}

// ─── MFA Setup Component ──────────────────────────────────────────────────────
function MFASetupSection() {
  const utils = trpc.useUtils();
  const mfaStatus = trpc.accountAuth.mfaStatus.useQuery();
  const mfaSetup = trpc.accountAuth.mfaSetup.useMutation();
  const mfaVerifyAndEnable = trpc.accountAuth.mfaVerifyAndEnable.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success("MFA enabled successfully");
        setSetupStep("done");
        utils.accountAuth.mfaStatus.invalidate();
      } else {
        toast.error(data.message || "Invalid code");
      }
    },
    onError: (err) => toast.error(err.message),
  });
  const mfaDisable = trpc.accountAuth.mfaDisable.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success("MFA has been disabled");
        setDisableDialogOpen(false);
        setDisableCode("");
        utils.accountAuth.mfaStatus.invalidate();
      } else {
        toast.error(data.message || "Invalid code");
      }
    },
    onError: (err) => toast.error(err.message),
  });
  const mfaRegenBackupCodes = trpc.accountAuth.mfaRegenerateBackupCodes.useMutation({
    onSuccess: (data) => {
      if (data.success && data.backupCodes) {
        setRegenCodes(data.backupCodes);
        setRegenDialogOpen(false);
        setRegenCode("");
        setShowRegenCodes(true);
        utils.accountAuth.mfaStatus.invalidate();
        toast.success("Backup codes regenerated — save them now!");
      } else {
        toast.error(data.message || "Invalid code");
      }
    },
    onError: (err) => toast.error(err.message),
  });

  const [setupStep, setSetupStep] = useState<"idle" | "qr" | "verify" | "done">("idle");
  const [setupData, setSetupData] = useState<{ secret: string; qrCode: string; backupCodes: string[] } | null>(null);
  const [verifyCode, setVerifyCode] = useState("");
  const [showBackupCodes, setShowBackupCodes] = useState(false);
  const [disableDialogOpen, setDisableDialogOpen] = useState(false);
  const [disableCode, setDisableCode] = useState("");
  const [regenDialogOpen, setRegenDialogOpen] = useState(false);
  const [regenCode, setRegenCode] = useState("");
  const [regenCodes, setRegenCodes] = useState<string[] | null>(null);
  const [showRegenCodes, setShowRegenCodes] = useState(false);

  const handleStartSetup = async () => {
    try {
      const result = await mfaSetup.mutateAsync();
      setSetupData({
        secret: result.secret,
        qrCode: result.qrCode,
        backupCodes: result.backupCodes,
      });
      setSetupStep("qr");
    } catch (err: any) {
      toast.error(err.message || "Failed to start MFA setup");
    }
  };

  const handleVerify = () => {
    if (verifyCode.length !== 6) {
      toast.error("Please enter a 6-digit code");
      return;
    }
    mfaVerifyAndEnable.mutate({ code: verifyCode });
  };

  const handleDisable = () => {
    if (disableCode.length < 6) {
      toast.error("Please enter a valid code");
      return;
    }
    mfaDisable.mutate({ code: disableCode });
  };

  const isEnabled = mfaStatus.data?.enabled;
  const backupCodesRemaining = mfaStatus.data?.backupCodesRemaining ?? 0;

  if (!mfaStatus.data?.available) {
    return (
      <div className="p-4 bg-muted/30 rounded-lg text-center">
        <p className="text-sm text-muted-foreground">MFA is only available for email-based accounts.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {isEnabled && setupStep !== "done" ? (
        /* MFA is enabled — show status and disable option */
        <div className="space-y-4">
          <div className="flex items-center gap-3 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
            <ShieldCheck className="w-6 h-6 text-emerald-500" />
            <div className="flex-1">
              <p className="text-sm font-semibold text-emerald-400">MFA Enabled</p>
              <p className="text-xs text-muted-foreground">
                Your account is protected with TOTP-based multi-factor authentication.
                {backupCodesRemaining > 0 && ` ${backupCodesRemaining} backup codes remaining.`}
              </p>
            </div>
          </div>

          {backupCodesRemaining <= 2 && backupCodesRemaining > 0 && (
            <div className="flex items-center gap-3 p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-amber-500" />
              <p className="text-xs text-amber-400">
                You have only {backupCodesRemaining} backup code{backupCodesRemaining === 1 ? "" : "s"} remaining.
                Consider regenerating your MFA setup to get new backup codes.
              </p>
            </div>
          )}

          <div className="flex gap-3">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setRegenDialogOpen(true)}
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              REGENERATE BACKUP CODES
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setDisableDialogOpen(true)}
            >
              <ShieldOff className="w-4 h-4 mr-2" />
              DISABLE MFA
            </Button>
          </div>

          {/* Regenerated backup codes display */}
          {showRegenCodes && regenCodes && (
            <div className="p-4 bg-card border border-primary/30 rounded-lg">
              <h3 className="font-display text-sm tracking-wider mb-3 flex items-center gap-2">
                <Key className="w-4 h-4 text-primary" />
                NEW BACKUP CODES
              </h3>
              <p className="text-xs text-amber-400 mb-3">
                Save these codes now — they will not be shown again. Your previous codes are no longer valid.
              </p>
              <div className="grid grid-cols-2 gap-2 mb-3">
                {regenCodes.map((code, i) => (
                  <code key={i} className="text-xs font-mono bg-secondary/50 p-2 rounded text-center">
                    {code}
                  </code>
                ))}
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    navigator.clipboard.writeText(regenCodes.join("\n"));
                    toast.success("Backup codes copied to clipboard");
                  }}
                >
                  <Copy className="w-3.5 h-3.5 mr-1" /> Copy All
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => { setShowRegenCodes(false); setRegenCodes(null); }}
                >
                  Done
                </Button>
              </div>
            </div>
          )}

          {/* Regenerate Backup Codes Dialog */}
          <Dialog open={regenDialogOpen} onOpenChange={setRegenDialogOpen}>
            <DialogContent className="sm:max-w-sm">
              <DialogHeader>
                <DialogTitle className="font-display tracking-wider">REGENERATE BACKUP CODES</DialogTitle>
                <DialogDescription>
                  Enter your current authenticator code to generate new backup codes. All existing backup codes will be invalidated.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Authenticator Code</Label>
                  <Input
                    type="text"
                    inputMode="numeric"
                    placeholder="6-digit TOTP code"
                    value={regenCode}
                    onChange={(e) => setRegenCode(e.target.value.replace(/\D/g, "").substring(0, 6))}
                    className="text-center text-lg tracking-[0.3em] font-mono"
                    maxLength={6}
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setRegenDialogOpen(false)}>Cancel</Button>
                <Button
                  onClick={() => mfaRegenBackupCodes.mutate({ code: regenCode })}
                  disabled={regenCode.length !== 6 || mfaRegenBackupCodes.isPending}
                >
                  {mfaRegenBackupCodes.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
                  Regenerate
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* Disable MFA Dialog */}
          <Dialog open={disableDialogOpen} onOpenChange={setDisableDialogOpen}>
            <DialogContent className="sm:max-w-sm">
              <DialogHeader>
                <DialogTitle className="font-display tracking-wider">DISABLE MFA</DialogTitle>
                <DialogDescription>
                  Enter your current authenticator code or a backup code to disable MFA.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Verification Code</Label>
                  <Input
                    type="text"
                    inputMode="numeric"
                    placeholder="6-digit TOTP or 8-char backup code"
                    value={disableCode}
                    onChange={(e) => setDisableCode(e.target.value.replace(/[^A-Za-z0-9]/g, "").substring(0, 8))}
                    className="text-center text-lg tracking-[0.3em] font-mono"
                    maxLength={8}
                  />
                </div>
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                  <p className="text-xs text-red-400">
                    Disabling MFA will reduce your account security. You can re-enable it at any time.
                  </p>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setDisableDialogOpen(false)}>Cancel</Button>
                <Button
                  variant="destructive"
                  onClick={handleDisable}
                  disabled={disableCode.length < 6 || mfaDisable.isPending}
                >
                  {mfaDisable.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
                  Disable MFA
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      ) : setupStep === "idle" ? (
        /* MFA not enabled — show setup button */
        <div className="space-y-4">
          <div className="flex items-center gap-3 p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg">
            <AlertTriangle className="w-6 h-6 text-amber-500" />
            <div className="flex-1">
              <p className="text-sm font-semibold text-amber-400">MFA Not Enabled</p>
              <p className="text-xs text-muted-foreground">
                Enable multi-factor authentication to meet FedRAMP High compliance requirements.
                You'll need an authenticator app like Google Authenticator, Authy, or 1Password.
              </p>
            </div>
          </div>
          <Button onClick={handleStartSetup} disabled={mfaSetup.isPending}>
            {mfaSetup.isPending ? (
              <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> SETTING UP...</>
            ) : (
              <><QrCode className="w-4 h-4 mr-2" /> SET UP MFA</>
            )}
          </Button>
        </div>
      ) : setupStep === "qr" && setupData ? (
        /* Step 1: Show QR code and secret */
        <div className="space-y-4">
          <div className="p-4 bg-card border border-border rounded-lg">
            <h3 className="font-display text-sm tracking-wider mb-3 flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-primary/20 text-primary text-xs flex items-center justify-center font-bold">1</span>
              SCAN QR CODE
            </h3>
            <p className="text-xs text-muted-foreground mb-4">
              Open your authenticator app and scan this QR code, or manually enter the secret key below.
            </p>
            <div className="flex flex-col items-center gap-4">
              <div className="bg-white p-3 rounded-lg">
                <img src={setupData.qrCode} alt="MFA QR Code" className="w-48 h-48" />
              </div>
              <div className="w-full">
                <Label className="text-xs text-muted-foreground">Manual Entry Key</Label>
                <div className="flex items-center gap-2 mt-1">
                  <code className="flex-1 text-xs font-mono bg-secondary/50 p-2 rounded break-all select-all">
                    {setupData.secret}
                  </code>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 w-8 p-0 shrink-0"
                    onClick={() => {
                      navigator.clipboard.writeText(setupData.secret);
                      toast.success("Secret copied to clipboard");
                    }}
                  >
                    <Copy className="w-3.5 h-3.5" />
                  </Button>
                </div>
              </div>
            </div>
          </div>

          {/* Backup codes */}
          <div className="p-4 bg-card border border-border rounded-lg">
            <h3 className="font-display text-sm tracking-wider mb-3 flex items-center gap-2">
              <Key className="w-4 h-4 text-amber-500" />
              BACKUP CODES
            </h3>
            <p className="text-xs text-muted-foreground mb-3">
              Save these backup codes in a secure location. Each code can only be used once.
            </p>
            <div className="flex items-center gap-2 mb-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowBackupCodes(!showBackupCodes)}
              >
                {showBackupCodes ? <EyeOff className="w-3.5 h-3.5 mr-1" /> : <Eye className="w-3.5 h-3.5 mr-1" />}
                {showBackupCodes ? "Hide" : "Show"} Codes
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  navigator.clipboard.writeText(setupData.backupCodes.join("\n"));
                  toast.success("Backup codes copied to clipboard");
                }}
              >
                <Copy className="w-3.5 h-3.5 mr-1" /> Copy All
              </Button>
            </div>
            {showBackupCodes && (
              <div className="grid grid-cols-2 gap-2">
                {setupData.backupCodes.map((code, i) => (
                  <code key={i} className="text-xs font-mono bg-secondary/50 p-2 rounded text-center">
                    {code}
                  </code>
                ))}
              </div>
            )}
          </div>

          <div className="flex gap-3">
            <Button variant="outline" onClick={() => { setSetupStep("idle"); setSetupData(null); }}>
              Cancel
            </Button>
            <Button onClick={() => setSetupStep("verify")}>
              Continue to Verification
            </Button>
          </div>
        </div>
      ) : setupStep === "verify" ? (
        /* Step 2: Verify TOTP code */
        <div className="space-y-4">
          <div className="p-4 bg-card border border-border rounded-lg">
            <h3 className="font-display text-sm tracking-wider mb-3 flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-primary/20 text-primary text-xs flex items-center justify-center font-bold">2</span>
              VERIFY SETUP
            </h3>
            <p className="text-xs text-muted-foreground mb-4">
              Enter the 6-digit code from your authenticator app to confirm setup.
            </p>
            <div className="space-y-3">
              <Input
                type="text"
                inputMode="numeric"
                placeholder="000000"
                value={verifyCode}
                onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, "").substring(0, 6))}
                className="text-center text-2xl tracking-[0.5em] font-mono max-w-xs mx-auto"
                maxLength={6}
              />
              <div className="flex gap-3 justify-center">
                <Button variant="outline" onClick={() => setSetupStep("qr")}>
                  Back
                </Button>
                <Button
                  onClick={handleVerify}
                  disabled={verifyCode.length !== 6 || mfaVerifyAndEnable.isPending}
                >
                  {mfaVerifyAndEnable.isPending ? (
                    <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> VERIFYING...</>
                  ) : (
                    <><ShieldCheck className="w-4 h-4 mr-2" /> ENABLE MFA</>
                  )}
                </Button>
              </div>
            </div>
          </div>
        </div>
      ) : setupStep === "done" ? (
        /* Setup complete */
        <div className="flex items-center gap-3 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
          <CheckCircle2 className="w-6 h-6 text-emerald-500" />
          <div>
            <p className="text-sm font-semibold text-emerald-400">MFA Successfully Enabled</p>
            <p className="text-xs text-muted-foreground">
              Your account is now protected with TOTP-based multi-factor authentication.
            </p>
          </div>
        </div>
      ) : null}
    </div>
  );
}

// ─── My Sessions Component ────────────────────────────────────────────────────
function MySessionsSection() {
  const mySessions = trpc.accountAuth.mySessions.useQuery();

  return (
    <div className="space-y-3">
      {mySessions.isLoading ? (
        <div className="space-y-2">
          {[1, 2].map((i) => (
            <div key={i} className="h-14 bg-secondary/30 rounded animate-pulse" />
          ))}
        </div>
      ) : !mySessions.data?.length ? (
        <p className="text-sm text-muted-foreground text-center py-4">No active sessions found.</p>
      ) : (
        <div className="space-y-2">
          {mySessions.data.map((session) => (
            <div
              key={session.id}
              className={`flex items-center gap-3 p-3 rounded-lg border ${
                session.isCurrent
                  ? "border-primary/30 bg-primary/5"
                  : "border-border bg-card"
              }`}
            >
              <Monitor className="w-5 h-5 text-muted-foreground shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium">{session.deviceInfo || "Unknown device"}</span>
                  {session.isCurrent && (
                    <span className="text-[9px] font-display tracking-widest px-1.5 py-0.5 rounded bg-primary/20 text-primary">
                      CURRENT
                    </span>
                  )}
                </div>
                <p className="text-[10px] text-muted-foreground">
                  {session.ipAddress || "Unknown IP"} — Last active: {session.lastActivityAt ? new Date(session.lastActivityAt).toLocaleString() : "Unknown"}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AccountSettings() {
  const { user } = useAuth();
  const profile = trpc.account.getProfile.useQuery(undefined, { enabled: !!user });
  const compliance = trpc.account.getComplianceStatus.useQuery(undefined, {
    enabled: !!user && (user.role === "admin" || user.role === "team_lead"),
  });
  const updateProfile = trpc.account.updateProfile.useMutation({
    onSuccess: () => {
      toast.success("Profile updated successfully");
      profile.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const [formData, setFormData] = useState<{
    name?: string;
    title?: string;
    department?: string;
    phone?: string;
    timezone?: string;
  }>({});

  const p = profile.data;
  const isAdmin = user?.role === "admin" || user?.role === "team_lead";

  const handleSave = () => {
    const updates: Record<string, string> = {};
    if (formData.name !== undefined && formData.name !== p?.name) updates.name = formData.name;
    if (formData.title !== undefined && formData.title !== p?.title) updates.title = formData.title;
    if (formData.department !== undefined && formData.department !== p?.department) updates.department = formData.department;
    if (formData.phone !== undefined && formData.phone !== p?.phone) updates.phone = formData.phone;
    if (formData.timezone !== undefined && formData.timezone !== p?.timezone) updates.timezone = formData.timezone;

    if (Object.keys(updates).length === 0) {
      toast.info("No changes to save");
      return;
    }
    updateProfile.mutate(updates);
  };

  return (
    <AppShell activePath="/account-settings">
      <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <UserCog className="w-6 h-6 text-primary" />
            <div>
              <h1 className="font-display text-2xl tracking-wider">MY ACCOUNT</h1>
              <p className="text-sm text-muted-foreground">Profile, security, and compliance settings</p>
            </div>
          </div>
          <Button onClick={handleSave} disabled={updateProfile.isPending}>
            {updateProfile.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
            SAVE CHANGES
          </Button>
        </div>
        <div className="w-full h-1 bg-primary" />
      </header>

      <div className="p-6 space-y-6 max-w-5xl">
        {/* Profile Card */}
        <Card className="border-2 border-border">
          <CardHeader>
            <CardTitle className="font-display tracking-wider flex items-center gap-2">
              <UserCog className="w-5 h-5" /> PROFILE INFORMATION
            </CardTitle>
            <CardDescription>Your personal details and contact information</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="name">Display Name</Label>
                <Input
                  id="name"
                  defaultValue={p?.name || ""}
                  onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
                  placeholder="Your display name"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <div className="flex items-center gap-2">
                  <Mail className="w-4 h-4 text-muted-foreground" />
                  <span className="text-sm text-muted-foreground">{p?.email || "Not set"}</span>
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="title">Job Title</Label>
                <Input
                  id="title"
                  defaultValue={p?.title || ""}
                  onChange={(e) => setFormData((prev) => ({ ...prev, title: e.target.value }))}
                  placeholder="e.g. Senior Penetration Tester"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="department">Department</Label>
                <Input
                  id="department"
                  defaultValue={p?.department || ""}
                  onChange={(e) => setFormData((prev) => ({ ...prev, department: e.target.value }))}
                  placeholder="e.g. Offensive Security"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="phone">Phone</Label>
                <div className="flex items-center gap-2">
                  <Phone className="w-4 h-4 text-muted-foreground" />
                  <Input
                    id="phone"
                    defaultValue={p?.phone || ""}
                    onChange={(e) => setFormData((prev) => ({ ...prev, phone: e.target.value }))}
                    placeholder="+1 (555) 000-0000"
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="timezone">Timezone</Label>
                <Select
                  defaultValue={p?.timezone || "America/New_York"}
                  onValueChange={(val) => setFormData((prev) => ({ ...prev, timezone: val }))}
                >
                  <SelectTrigger>
                    <Globe className="w-4 h-4 mr-2" />
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TIMEZONES.map((tz) => (
                      <SelectItem key={tz} value={tz}>{tz}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="pt-2 flex items-center gap-3">
              <span className="text-xs px-2 py-1 rounded bg-primary/10 text-primary font-mono uppercase">
                {ROLE_LABELS[p?.role || "operator"] || p?.role}
              </span>
              <span className="text-xs text-muted-foreground">
                Login method: {p?.loginMethod || "OAuth"}
              </span>
              {p?.lastSignedIn && (
                <span className="text-xs text-muted-foreground flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Last login: {new Date(p.lastSignedIn).toLocaleString()}
                </span>
              )}
            </div>
          </CardContent>
        </Card>

        {/* MFA / Two-Factor Authentication Card */}
        <Card className="border-2 border-border">
          <CardHeader>
            <CardTitle className="font-display tracking-wider flex items-center gap-2">
              <Fingerprint className="w-5 h-5" /> MULTI-FACTOR AUTHENTICATION
            </CardTitle>
            <CardDescription>
              TOTP-based MFA using authenticator apps. Required for FedRAMP High compliance (NIST SP 800-63B AAL2).
            </CardDescription>
          </CardHeader>
          <CardContent>
            <MFASetupSection />
          </CardContent>
        </Card>

        {/* Active Sessions Card */}
        <Card className="border-2 border-border">
          <CardHeader>
            <CardTitle className="font-display tracking-wider flex items-center gap-2">
              <Monitor className="w-5 h-5" /> ACTIVE SESSIONS
            </CardTitle>
            <CardDescription>Devices and browsers currently signed in to your account</CardDescription>
          </CardHeader>
          <CardContent>
            <MySessionsSection />
          </CardContent>
        </Card>

        {/* Security Status Card */}
        <Card className="border-2 border-border">
          <CardHeader>
            <CardTitle className="font-display tracking-wider flex items-center gap-2">
              <Shield className="w-5 h-5" /> SECURITY STATUS
            </CardTitle>
            <CardDescription>Authentication and access security posture</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-3 gap-4">
              <div className="p-4 rounded-lg bg-card border border-border">
                <div className="flex items-center gap-2 mb-2">
                  <Lock className="w-5 h-5 text-primary" />
                  <span className="font-display text-sm tracking-wider">AUTH PROVIDER</span>
                </div>
                <p className="text-lg font-semibold">Email + TOTP</p>
                <p className="text-xs text-muted-foreground mt-1">FIPS 140-3 compliant bcrypt-12</p>
              </div>
              <div className="p-4 rounded-lg bg-card border border-border">
                <div className="flex items-center gap-2 mb-2">
                  <Fingerprint className="w-5 h-5 text-green-500" />
                  <span className="font-display text-sm tracking-wider">MFA STATUS</span>
                </div>
                <p className="text-lg font-semibold flex items-center gap-2">
                  {p?.mfaEnabled ? (
                    <><CheckCircle2 className="w-5 h-5 text-green-500" /> Enabled</>
                  ) : (
                    <><AlertTriangle className="w-5 h-5 text-yellow-500" /> Not Enabled</>
                  )}
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  TOTP-based authenticator app MFA
                </p>
              </div>
              <div className="p-4 rounded-lg bg-card border border-border">
                <div className="flex items-center gap-2 mb-2">
                  <Key className="w-5 h-5 text-blue-500" />
                  <span className="font-display text-sm tracking-wider">SESSION</span>
                </div>
                <p className="text-lg font-semibold">HttpOnly Secure</p>
                <p className="text-xs text-muted-foreground mt-1">
                  SameSite cookies, HMAC-SHA256 JWTs
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Change Password Card */}
        <Card className="border-2 border-border">
          <CardHeader>
            <CardTitle className="font-display tracking-wider flex items-center gap-2">
              <Lock className="w-5 h-5" /> CHANGE PASSWORD
            </CardTitle>
            <CardDescription>Update your account password. Must meet NIST SP 800-63B requirements (min 12 characters, mixed case, number, special character).</CardDescription>
          </CardHeader>
          <CardContent>
            <PasswordChangeForm />
          </CardContent>
        </Card>

        {/* FIPS Compliance Card (Admin only) */}
        {isAdmin && compliance.data && (
          <Card className="border-2 border-primary/30">
            <CardHeader>
              <CardTitle className="font-display tracking-wider flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-primary" /> FIPS 140-3 COMPLIANCE
              </CardTitle>
              <CardDescription>Federal Information Processing Standards compliance status</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid md:grid-cols-2 gap-4">
                <div className="space-y-3">
                  <h3 className="font-display text-sm tracking-wider text-muted-foreground">CRYPTOGRAPHIC MODULE</h3>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Provider</span>
                      <span className="font-mono">{compliance.data.fips140_3.cryptoProvider}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>OpenSSL</span>
                      <span className="font-mono text-xs">{compliance.data.fips140_3.opensslVersion}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>FIPS Provider Active</span>
                      <span>{compliance.data.fips140_3.fipsProviderActive ? "✓" : "Software mode"}</span>
                    </div>
                  </div>
                </div>
                <div className="space-y-3">
                  <h3 className="font-display text-sm tracking-wider text-muted-foreground">TLS ENFORCEMENT</h3>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Global Enforcement</span>
                      <span className={compliance.data.tls.enforced ? "text-green-500" : "text-yellow-500"}>
                        {compliance.data.tls.enforced ? "Active" : "Pending"}
                      </span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>Min TLS Version</span>
                      <span className="font-mono">{compliance.data.tls.minVersion}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>FIPS Cipher Suites</span>
                      <span>{compliance.data.tls.cipherSuiteCount} approved</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-4">
                <h3 className="font-display text-sm tracking-wider text-muted-foreground mb-3">STANDARDS ALIGNMENT</h3>
                <div className="grid md:grid-cols-3 gap-2">
                  {compliance.data.standards.map((s) => (
                    <div key={s.name} className="flex items-center gap-2 p-2 rounded bg-card border border-border">
                      <CheckCircle2 className={`w-4 h-4 ${s.status === "certified" || s.status === "compliant" ? "text-green-500" : "text-blue-500"}`} />
                      <div>
                        <span className="text-xs font-semibold">{s.name}</span>
                        <span className="text-xs text-muted-foreground ml-1 capitalize">({s.status.replace("_", " ")})</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-4 p-3 rounded bg-primary/5 border border-primary/20">
                <h3 className="font-display text-sm tracking-wider mb-2">DATA PROTECTION</h3>
                <div className="grid md:grid-cols-2 gap-2 text-xs">
                  <div><span className="text-muted-foreground">At Rest:</span> {compliance.data.dataProtection.atRest}</div>
                  <div><span className="text-muted-foreground">In Transit:</span> {compliance.data.dataProtection.inTransit}</div>
                  <div><span className="text-muted-foreground">Key Mgmt:</span> {compliance.data.dataProtection.keyManagement}</div>
                  <div><span className="text-muted-foreground">Invite Tokens:</span> {compliance.data.dataProtection.inviteTokens}</div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}
