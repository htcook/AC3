import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { useLocation } from "wouter";
import { Cloud, Lock, User, Shield, AlertTriangle } from "lucide-react";

export default function Login() {
  const [, setLocation] = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const utils = trpc.useUtils();
  
  const loginMutation = trpc.calderaAuth.login.useMutation({
    onSuccess: async (data: { success: boolean; message?: string }) => {
      if (data.success) {
        toast.success("Login successful", {
          description: "Welcome to Ace Strike Platform",
        });
        // Invalidate the session query to force a refetch
        await utils.calderaAuth.session.invalidate();
        // Small delay to ensure cookie is set
        setTimeout(() => {
          window.location.href = "/dashboard";
        }, 100);
      } else {
        toast.error("Login failed", {
          description: data.message || "Invalid credentials",
        });
        setIsLoading(false);
      }
    },
    onError: (error: { message?: string }) => {
      toast.error("Login failed", {
        description: error.message || "Unable to authenticate",
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
    setIsLoading(true);
    loginMutation.mutate({ username, password });
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
          <h1 className="font-display text-4xl tracking-tight text-foreground mb-2">
            CALDERA <span className="text-primary">COMMAND</span>
          </h1>
          <p className="text-muted-foreground">Secure Access Portal</p>
        </div>

        <Card className="border-border/50 bg-card/80 backdrop-blur">
          <CardHeader className="text-center pb-4">
            <div className="mx-auto w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mb-4">
              <Shield className="w-8 h-8 text-primary" />
            </div>
            <CardTitle className="font-display text-xl tracking-wide">AUTHENTICATION REQUIRED</CardTitle>
            <CardDescription>
              Enter your Caldera administrator credentials to access the Command Center
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

            <div className="mt-6 p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg">
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
