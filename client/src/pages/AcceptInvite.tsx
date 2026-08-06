import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  CheckCircle2,
  XCircle,
  Loader2,
  Shield,
  UserPlus,
  Key,
  Clock,
} from "lucide-react";
import { useLocation } from "wouter";

export default function AcceptInvite() {
  const { user } = useAuth();
  const [, navigate] = useLocation();
  const [token, setToken] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const validation = trpc.account.validateInvite.useQuery(
    { token },
    { enabled: token.length > 20 && !submitted }
  );

  const acceptInvite = trpc.account.acceptInvite.useMutation({
    onSuccess: (data) => {
      setSubmitted(true);
      toast.success(`Welcome! You've been assigned the ${data.role} role.`);
      setTimeout(() => navigate("/"), 2000);
    },
    onError: (err) => toast.error(err.message),
  });

  const handleAccept = () => {
    if (!token) {
      toast.error("Please enter your invitation token");
      return;
    }
    acceptInvite.mutate({ token });
  };

  return (
    <AppShell activePath="/invitations">
      <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="px-6 py-4">
          <div className="flex items-center gap-3">
            <UserPlus className="w-6 h-6 text-primary" />
            <div>
              <h1 className="font-display text-2xl tracking-wider">ACCEPT INVITATION</h1>
              <p className="text-sm text-muted-foreground">Enter your invitation token to join the team</p>
            </div>
          </div>
        </div>
        <div className="w-full h-1 bg-primary" />
      </header>

      <div className="p-6 max-w-xl mx-auto">
        {submitted ? (
          <Card className="border-2 border-green-500/30">
            <CardContent className="p-8 text-center">
              <CheckCircle2 className="w-16 h-16 text-green-500 mx-auto mb-4" />
              <h2 className="text-xl font-display tracking-wider mb-2">INVITATION ACCEPTED</h2>
              <p className="text-muted-foreground">Redirecting to your dashboard...</p>
            </CardContent>
          </Card>
        ) : (
          <Card className="border-2 border-border">
            <CardHeader>
              <CardTitle className="font-display tracking-wider flex items-center gap-2">
                <Key className="w-5 h-5" /> INVITATION TOKEN
              </CardTitle>
              <CardDescription>
                Paste the invitation token you received from your team administrator.
                Tokens are verified using SHA-256 hashing (FIPS 140-3 compliant).
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="token">Invitation Token</Label>
                <Input
                  id="token"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="Paste your invitation token here..."
                  className="font-mono text-sm"
                />
              </div>

              {/* Validation status */}
              {token.length > 20 && validation.data && (
                <div className={`p-4 rounded-lg border ${
                  validation.data.valid
                    ? "bg-green-500/10 border-green-500/30"
                    : "bg-red-500/10 border-red-500/30"
                }`}>
                  {validation.data.valid ? (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-5 h-5 text-green-500" />
                        <span className="font-semibold text-green-500">Valid Invitation</span>
                      </div>
                      <div className="text-sm space-y-1">
                        <p>Email: <strong>{validation.data.email}</strong></p>
                        <p>Role: <strong className="capitalize">{validation.data.role?.replace("_", " ")}</strong></p>
                        <p>Invited by: <strong>{validation.data.invitedByName}</strong></p>
                        {validation.data.message && (
                          <p className="italic text-muted-foreground">"{validation.data.message}"</p>
                        )}
                        <p className="flex items-center gap-1 text-xs text-muted-foreground">
                          <Clock className="w-3 h-3" />
                          Expires: {validation.data.expiresAt ? new Date(validation.data.expiresAt).toLocaleString() : "Unknown"}
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <XCircle className="w-5 h-5 text-red-500" />
                      <span className="text-red-500">{validation.data.reason}</span>
                    </div>
                  )}
                </div>
              )}

              {validation.isLoading && token.length > 20 && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Validating token...
                </div>
              )}

              <Button
                onClick={handleAccept}
                disabled={!validation.data?.valid || acceptInvite.isPending}
                className="w-full font-display tracking-wider"
              >
                {acceptInvite.isPending ? (
                  <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> ACCEPTING...</>
                ) : (
                  <><Shield className="w-4 h-4 mr-2" /> ACCEPT INVITATION</>
                )}
              </Button>

              <div className="text-xs text-muted-foreground text-center space-y-1">
                <p>Your current account will be assigned the invited role.</p>
                <p className="flex items-center justify-center gap-1">
                  <Shield className="w-3 h-3" />
                  FIPS 140-3 compliant token verification
                </p>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}
