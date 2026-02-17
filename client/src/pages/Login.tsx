import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { useLocation, useSearch } from "wouter";
import { Cloud, Lock, User, Shield, AlertTriangle } from "lucide-react";

const REDIRECT_MAP: Record<string, { label: string; url: string }> = {
  caldera: { label: "MITRE Caldera", url: "https://caldera.aceofcloud.io" },
  gophish: { label: "GoPhish Admin", url: "https://gophish.aceofcloud.io" },
};

export default function Login() {
  const [, setLocation] = useLocation();
  const searchString = useSearch();
  const params = new URLSearchParams(searchString);
  const redirectTarget = params.get("redirect") || "";
  const redirectInfo = REDIRECT_MAP[redirectTarget];

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const utils = trpc.useUtils();
  
  // Check if already authenticated - if so, redirect immediately
  const { data: session, isLoading: sessionLoading } = trpc.calderaAuth.session.useQuery();
  
  useEffect(() => {
    if (!sessionLoading && session?.authenticated) {
      if (redirectTarget && redirectInfo) {
        // Already logged in, redirect to the target service
        window.location.href = redirectInfo.url;
      } else {
        window.location.href = "/dashboard";
      }
    }
  }, [sessionLoading, session, redirectTarget, redirectInfo]);

  const loginMutation = trpc.calderaAuth.login.useMutation({
    onSuccess: (data: { success: boolean; message?: string }) => {
      if (data.success) {
        toast.success("Login successful", {
          description: redirectInfo
            ? `Authenticating with ${redirectInfo.label}...`
            : "Welcome to Ace C3",
        });
        // Invalidate the session query so ProtectedRoute sees the new auth state,
        // then redirect. Using a delay + window.location.href ensures the
        // Set-Cookie header is fully committed by the browser before navigating.
        // Mobile Safari in particular can race between cookie persistence and
        // navigation.
        utils.calderaAuth.session.invalidate().then(() => {
          setTimeout(() => {
            if (redirectTarget && redirectInfo) {
              window.location.href = redirectInfo.url;
            } else {
              window.location.href = "/dashboard";
            }
          }, 500);
        });
      } else {
        toast.error("Login failed", {
          description: data.message || "Invalid credentials",
        });
        setIsLoading(false);
      }
    },
    onError: (error: any) => {
      console.error('[Login] Mutation error:', error?.message, error);
      console.error('[Login] Full error object:', JSON.stringify(error, null, 2));
      toast.error("Login failed", {
        description: error?.message || "Unable to authenticate. Please try again.",
      });
      setIsLoading(false);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      toast.error("Please enter both username and password");
      return;
    }
    // Debug: log what the browser is actually sending
    console.log('[Login] Submitting:', {
      username,
      passwordLen: password.length,
      passwordFirst: password.charAt(0),
      passwordLast: password.charAt(password.length - 1),
      passwordChars: Array.from(password).map((c, i) => `${i}:${c.charCodeAt(0)}`).join(','),
    });
    setIsLoading(true);
    loginMutation.mutate({ username, password, rememberMe });
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
              One login for Dashboard, Caldera, and GoPhish
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
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username" className="text-sm font-medium">
                  Username
                </Label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    id="username"
                    type="text"
                    placeholder="admin"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="pl-10 bg-background/50"
                    disabled={isLoading}
                  />
                </div>
              </div>

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

            {/* Unified auth info */}
            <div className="mt-4 p-3 bg-muted/50 rounded-lg">
              <p className="text-xs text-muted-foreground text-center">
                Single sign-on for all services: Dashboard, MITRE Caldera, and GoPhish
              </p>
            </div>

            <div className="mt-4 p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-medium text-amber-500 mb-1">Security Notice</p>
                  <p className="text-muted-foreground">
                    This system is for authorized personnel only. All access attempts are logged and monitored.
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <p className="text-center text-sm text-muted-foreground mt-6">
          Protected by <span className="text-primary font-medium">Ace of Cloud</span> Security
        </p>
      </div>
    </div>
  );
}
