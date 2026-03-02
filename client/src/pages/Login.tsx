import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { useSearch } from "wouter";
import { Cloud, Lock, User, Shield, AlertTriangle, Mail } from "lucide-react";

const REDIRECT_MAP: Record<string, { label: string; url: string }> = {
  caldera: { label: "the adversary emulation framework", url: "https://caldera.aceofcloud.io" },
  gophish: { label: "Phishing Admin", url: "https://gophish.aceofcloud.io" },
};

type LoginMode = "username" | "email";

export default function Login() {
  const searchString = useSearch();
  const params = new URLSearchParams(searchString);
  const redirectTarget = params.get("redirect") || "";
  const redirectInfo = REDIRECT_MAP[redirectTarget];

  const [loginMode, setLoginMode] = useState<LoginMode>("email");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Check if already authenticated
  const { data: session, isLoading: sessionLoading } = trpc.calderaAuth.session.useQuery();

  useEffect(() => {
    if (!sessionLoading && session?.authenticated) {
      if (redirectTarget && redirectInfo) {
        window.location.href = redirectInfo.url;
      } else {
        window.location.href = "/dashboard";
      }
    }
  }, [sessionLoading, session, redirectTarget, redirectInfo]);

  // Username login mutation (legacy)
  const usernameLoginMutation = trpc.calderaAuth.login.useMutation({
    onSuccess: (data: { success: boolean; message?: string }) => {
      if (data.success) {
        toast.success("Login successful", {
          description: redirectInfo
            ? `Authenticating with ${redirectInfo.label}...`
            : "Welcome to Ace C3",
        });
        const target = (redirectTarget && redirectInfo) ? redirectInfo.url : "/dashboard";
        setTimeout(() => { window.location.href = target; }, 300);
      } else {
        toast.error("Login failed", { description: data.message || "Invalid credentials" });
        setIsLoading(false);
      }
    },
    onError: (error: any) => {
      toast.error("Login failed", { description: error?.message || "Unable to authenticate." });
      setIsLoading(false);
    },
  });

  // Email login mutation (new FIPS-compliant)
  const emailLoginMutation = trpc.accountAuth.emailLogin.useMutation({
    onSuccess: (data: { success: boolean; message?: string }) => {
      if (data.success) {
        toast.success("Login successful", {
          description: redirectInfo
            ? `Authenticating with ${redirectInfo.label}...`
            : "Welcome to Ace C3",
        });
        const target = (redirectTarget && redirectInfo) ? redirectInfo.url : "/dashboard";
        setTimeout(() => { window.location.href = target; }, 300);
      } else {
        toast.error("Login failed", { description: data.message || "Invalid credentials" });
        setIsLoading(false);
      }
    },
    onError: (error: any) => {
      toast.error("Login failed", { description: error?.message || "Unable to authenticate." });
      setIsLoading(false);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    if (loginMode === "email") {
      if (!email || !password) {
        toast.error("Please enter both email and password");
        setIsLoading(false);
        return;
      }
      emailLoginMutation.mutate({ email, password, rememberMe });
    } else {
      if (!username || !password) {
        toast.error("Please enter both username and password");
        setIsLoading(false);
        return;
      }
      usernameLoginMutation.mutate({ username, password, rememberMe });
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      {/* Background grid effect */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(0,200,200,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,200,200,0.03)_1px,transparent_1px)] bg-[size:50px_50px]" />
      
      <div className="relative w-full max-w-md">
        {/* Logo and branding */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Cloud className="w-10 h-10 text-primary" />
            <span className="font-display text-2xl tracking-wider text-foreground">ACE OF CLOUD</span>
          </div>
          <h1 className="font-display text-2xl sm:text-3xl lg:text-4xl tracking-tight text-foreground mb-2">
            ACE <span className="text-primary">C3</span>
          </h1>
          <p className="text-muted-foreground">Cyber Campaign Command Platform</p>
        </div>

        {/* Redirect notice */}
        {redirectInfo && (
          <div className="mb-4 p-3 bg-primary/10 border border-primary/20 rounded-lg text-center">
            <p className="text-sm text-primary">
              Sign in to access <span className="font-semibold">{redirectInfo.label}</span>
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              One login for all platform services
            </p>
          </div>
        )}

        <Card className="border-border/50 bg-card/80 backdrop-blur">
          <CardHeader className="text-center pb-4">
            <div className="mx-auto w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mb-4">
              <Shield className="w-8 h-8 text-primary" />
            </div>
            <CardTitle className="font-display text-xl tracking-wide">AUTHENTICATION REQUIRED</CardTitle>
            <CardDescription>
              Enter your credentials to access Ace C3 and all connected services
            </CardDescription>
          </CardHeader>
          <CardContent>
            {/* Login mode tabs */}
            <div className="flex mb-6 bg-muted/50 rounded-lg p-1">
              <button
                type="button"
                onClick={() => setLoginMode("email")}
                className={`flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-md text-sm font-medium transition-all ${
                  loginMode === "email"
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                <Mail className="w-4 h-4" />
                Email
              </button>
              <button
                type="button"
                onClick={() => setLoginMode("username")}
                className={`flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-md text-sm font-medium transition-all ${
                  loginMode === "username"
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                <User className="w-4 h-4" />
                Service Account
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              {loginMode === "email" ? (
                <div className="space-y-2">
                  <Label htmlFor="email" className="text-sm font-medium">
                    Email Address
                  </Label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="email"
                      type="email"
                      placeholder="you@company.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="pl-10 bg-background/50"
                      disabled={isLoading}
                      autoComplete="email"
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <Label htmlFor="username" className="text-sm font-medium">
                    Username
                  </Label>
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="username"
                      type="text"
                      placeholder="red / blue / admin"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="pl-10 bg-background/50"
                      disabled={isLoading}
                      autoComplete="username"
                    />
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="password" className="text-sm font-medium">
                  Password
                </Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    id="password"
                    type="password"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="pl-10 bg-background/50"
                    disabled={isLoading}
                    autoComplete="current-password"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="rememberMe"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  disabled={isLoading}
                  className="h-4 w-4 rounded border-border bg-background/50 text-primary focus:ring-primary focus:ring-offset-0 cursor-pointer accent-primary"
                />
                <Label htmlFor="rememberMe" className="text-sm text-muted-foreground cursor-pointer select-none">
                  Remember me for 7 days
                </Label>
              </div>

              <Button
                type="submit"
                className="w-full font-display tracking-wider"
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin mr-2" />
                    AUTHENTICATING...
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4 mr-2" />
                    ACCESS COMMAND CENTER
                  </>
                )}
              </Button>
            </form>

            {/* SSO info */}
            <div className="mt-4 p-3 bg-muted/50 rounded-lg">
              <p className="text-xs text-muted-foreground text-center">
                {loginMode === "email"
                  ? "Sign in with your organizational email account"
                  : "Service accounts for automated integrations and legacy access"
                }
              </p>
            </div>

            <div className="mt-4 p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-medium text-amber-500 mb-1">Security Notice</p>
                  <p className="text-muted-foreground">
                    This system is for authorized personnel only. All access attempts are logged and monitored.
                    {loginMode === "email" && " Accounts are locked after 5 failed attempts (NIST SP 800-53 AC-7)."}
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <p className="text-center text-sm text-muted-foreground mt-6">
          Protected by <span className="text-primary font-medium">Ace of Cloud</span> Security
          <span className="block text-xs mt-1 opacity-60">FIPS 140-3 Compliant Authentication</span>
        </p>
      </div>
    </div>
  );
}
