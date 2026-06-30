import { Button } from "@/components/ui/button";
import { AlertTriangle, Home, ArrowLeft, Search } from "lucide-react";
import { useLocation } from "wouter";
import AppShell from "@/components/AppShell";

export default function NotFound() {
  const [location, setLocation] = useLocation();

  return (
    <AppShell activePath={location}>
      <div className="flex flex-col items-center justify-center min-h-[70vh] text-center px-4">
        {/* Glitch-style 404 */}
        <div className="relative mb-8">
          <div className="absolute inset-0 bg-destructive/10 rounded-full blur-3xl scale-150" />
          <div className="relative flex items-center gap-4">
            <AlertTriangle className="w-12 h-12 text-destructive/80" />
            <span className="font-display text-7xl sm:text-8xl tracking-widest text-destructive/90 font-bold">
              404
            </span>
          </div>
        </div>

        <h2 className="font-display text-xl sm:text-2xl tracking-wider text-foreground mb-3">
          SECTOR NOT FOUND
        </h2>

        <p className="text-muted-foreground max-w-md mb-2 text-sm leading-relaxed">
          The requested route <code className="px-2 py-0.5 bg-muted rounded text-xs font-mono text-primary">{location}</code> does not exist in the command matrix.
        </p>
        <p className="text-muted-foreground/60 text-xs mb-8">
          Use the sidebar navigation or search (⌘K) to find what you need.
        </p>

        <div className="flex flex-col sm:flex-row gap-3">
          <Button
            onClick={() => setLocation("/dashboard")}
            className="font-display tracking-wider"
          >
            <Home className="w-4 h-4 mr-2" />
            COMMAND CENTER
          </Button>
          <Button
            variant="outline"
            onClick={() => window.history.back()}
            className="font-display tracking-wider"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            GO BACK
          </Button>
        </div>

        {/* Suggested pages */}
        <div className="mt-12 border-t border-border/50 pt-8 w-full max-w-lg">
          <p className="text-[10px] font-display tracking-widest text-muted-foreground/50 uppercase mb-4">
            Quick Navigation
          </p>
          <div className="grid grid-cols-2 gap-2 text-xs">
            {[
              { href: "/engagements", label: "Engagements" },
              { href: "/domain-intel", label: "Domain Intel" },
              { href: "/agents", label: "Agents" },
              { href: "/exploit-catalog", label: "Exploit Catalog" },
              { href: "/threat-intel-hub", label: "Threat Intel" },
              { href: "/error-dashboard", label: "Error Dashboard" },
            ].map((link) => (
              <button
                key={link.href}
                onClick={() => setLocation(link.href)}
                className="px-3 py-2 bg-secondary/50 hover:bg-secondary rounded text-muted-foreground hover:text-foreground transition-colors font-display tracking-wider text-left"
              >
                {link.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </AppShell>
  );
}
