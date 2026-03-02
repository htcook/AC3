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
                <p className="text-lg font-semibold">Manus OAuth 2.0</p>
                <p className="text-xs text-muted-foreground mt-1">SAML 2.0 federation ready</p>
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
                    <><AlertTriangle className="w-5 h-5 text-yellow-500" /> Platform MFA</>
                  )}
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  WebAuthn/FIDO2 phishing-resistant MFA via OAuth provider
                </p>
              </div>
              <div className="p-4 rounded-lg bg-card border border-border">
                <div className="flex items-center gap-2 mb-2">
                  <Key className="w-5 h-5 text-blue-500" />
                  <span className="font-display text-sm tracking-wider">SESSION</span>
                </div>
                <p className="text-lg font-semibold">HttpOnly Secure</p>
                <p className="text-xs text-muted-foreground mt-1">
                  SameSite cookies, JWT signed tokens
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
