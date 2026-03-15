import { useState, useEffect } from "react";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Sparkles, Shield, Users, Scan, BarChart3, Lock,
  ArrowRight, X, ChevronRight
} from "lucide-react";

// ─── Release Notes Data ──────────────────────────────────────────────
// Update this array with each platform release. The component will show
// the pop-up whenever WHATS_NEW_VERSION changes.

export const WHATS_NEW_VERSION = "2026.03.01-v4";

interface ReleaseEntry {
  icon: React.ElementType;
  iconColor: string;
  tag: string;
  tagColor: string;
  title: string;
  description: string;
}

export const RELEASE_ENTRIES: ReleaseEntry[] = [
  {
    icon: Users,
    iconColor: "text-blue-400",
    tag: "NEW",
    tagColor: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    title: "Email-Based Account Management",
    description: "Invite team members by email with role-based access control. Manage accounts, reset passwords, and suspend/reactivate users from the Admin Dashboard. FIPS 140-3 and FedRAMP compliant.",
  },
  {
    icon: Shield,
    iconColor: "text-emerald-400",
    tag: "SECURITY",
    tagColor: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    title: "NIST SP 800-63B Password Policy",
    description: "Enforced 12-character minimum passwords with complexity requirements. Account lockout after 5 failed attempts. All auth events are audit-logged per FedRAMP AU-2/AU-3.",
  },
  {
    icon: Scan,
    iconColor: "text-cyan-400",
    tag: "IMPROVED",
    tagColor: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    title: "Dual Scan Modes: Full Discovery & Scoped",
    description: "Run full domain intelligence scans to discover all subdomains and assets, or use scoped scans limited to specific URLs and IPs within your Rules of Engagement.",
  },
  {
    icon: BarChart3,
    iconColor: "text-amber-400",
    tag: "IMPROVED",
    tagColor: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    title: "Scan List Sorting by Last Activity",
    description: "All scan lists now sort by most recently run or refreshed first. The Scan History page includes a Last Activity column for quick identification of recent scans.",
  },
  {
    icon: Sparkles,
    iconColor: "text-purple-400",
    tag: "NEW",
    tagColor: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    title: "Featured Threat Actors with ATT&CK Heatmap",
    description: "The dashboard now shows randomized featured threat actors ranked by data completeness, with mini ATT&CK technique heatmaps and a shuffle button for fresh intel on each visit.",
  },
  {
    icon: Lock,
    iconColor: "text-red-400",
    tag: "FIXED",
    tagColor: "bg-red-500/20 text-red-400 border-red-500/30",
    title: "Auth & Routing Hardened",
    description: "Public homepage now displays for unauthenticated visitors. Admin panel is no longer exposed without login. Red team operators correctly route to the Operator Dashboard.",
  },
];

// ─── Storage Key ─────────────────────────────────────────────────────
const STORAGE_KEY = "ac3_whats_new_dismissed";

function isDismissed(): boolean {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === WHATS_NEW_VERSION;
  } catch {
    return false;
  }
}

function dismiss(): void {
  try {
    localStorage.setItem(STORAGE_KEY, WHATS_NEW_VERSION);
  } catch {
    // localStorage unavailable
  }
}

// ─── Component ───────────────────────────────────────────────────────
export default function WhatsNew() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    // Show pop-up after a short delay if not dismissed for this version
    const timer = setTimeout(() => {
      if (!isDismissed()) {
        setOpen(true);
      }
    }, 800);
    return () => clearTimeout(timer);
  }, []);

  const handleDismiss = () => {
    dismiss();
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleDismiss(); }}>
      <DialogContent className="sm:max-w-lg max-h-[85vh] p-0 gap-0 overflow-hidden">
        {/* Header */}
        <div className="relative px-6 pt-6 pb-4 border-b border-border bg-gradient-to-br from-primary/5 to-transparent">
          <DialogHeader>
            <div className="flex items-center gap-2 mb-1">
              <Sparkles className="w-5 h-5 text-primary" />
              <DialogTitle className="font-display tracking-wider text-lg">WHAT'S NEW</DialogTitle>
              <Badge variant="outline" className="text-[9px] font-display tracking-widest ml-auto">
                {WHATS_NEW_VERSION}
              </Badge>
            </div>
            <DialogDescription className="text-sm">
              Here's what changed since your last visit. Review the updates below.
            </DialogDescription>
          </DialogHeader>
        </div>

        {/* Scrollable content */}
        <ScrollArea className="max-h-[55vh] px-6 py-4">
          <div className="space-y-4">
            {RELEASE_ENTRIES.map((entry, i) => (
              <div
                key={i}
                className="group flex gap-3 p-3 rounded-lg hover:bg-secondary/30 transition-colors"
              >
                {/* Icon */}
                <div className="shrink-0 mt-0.5">
                  <div className="w-8 h-8 rounded-lg bg-secondary/50 flex items-center justify-center">
                    <entry.icon className={`w-4 h-4 ${entry.iconColor}`} />
                  </div>
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-[8px] font-display tracking-widest px-1.5 py-0.5 rounded border ${entry.tagColor}`}>
                      {entry.tag}
                    </span>
                    <h4 className="text-sm font-medium">{entry.title}</h4>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {entry.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-border bg-secondary/10">
          <div className="flex items-center justify-between">
            <p className="text-[10px] text-muted-foreground">
              {RELEASE_ENTRIES.length} updates in this release
            </p>
            <Button onClick={handleDismiss} className="gap-1.5 font-display tracking-wider text-xs">
              GOT IT
              <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Trigger Button (for manual re-open) ─────────────────────────────
export function WhatsNewTrigger() {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="text-[10px] font-display tracking-wider gap-1.5 h-7"
        onClick={() => setOpen(true)}
      >
        <Sparkles className="w-3.5 h-3.5" />
        WHAT'S NEW
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-lg max-h-[85vh] p-0 gap-0 overflow-hidden">
          <div className="relative px-6 pt-6 pb-4 border-b border-border bg-gradient-to-br from-primary/5 to-transparent">
            <DialogHeader>
              <div className="flex items-center gap-2 mb-1">
                <Sparkles className="w-5 h-5 text-primary" />
                <DialogTitle className="font-display tracking-wider text-lg">WHAT'S NEW</DialogTitle>
                <Badge variant="outline" className="text-[9px] font-display tracking-widest ml-auto">
                  {WHATS_NEW_VERSION}
                </Badge>
              </div>
              <DialogDescription className="text-sm">
                Latest platform updates and improvements.
              </DialogDescription>
            </DialogHeader>
          </div>

          <ScrollArea className="max-h-[55vh] px-6 py-4">
            <div className="space-y-4">
              {RELEASE_ENTRIES.map((entry, i) => (
                <div key={i} className="group flex gap-3 p-3 rounded-lg hover:bg-secondary/30 transition-colors">
                  <div className="shrink-0 mt-0.5">
                    <div className="w-8 h-8 rounded-lg bg-secondary/50 flex items-center justify-center">
                      <entry.icon className={`w-4 h-4 ${entry.iconColor}`} />
                    </div>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-[8px] font-display tracking-widest px-1.5 py-0.5 rounded border ${entry.tagColor}`}>
                        {entry.tag}
                      </span>
                      <h4 className="text-sm font-medium">{entry.title}</h4>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">{entry.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>

          <div className="px-6 py-4 border-t border-border bg-secondary/10">
            <div className="flex items-center justify-between">
              <p className="text-[10px] text-muted-foreground">{RELEASE_ENTRIES.length} updates in this release</p>
              <Button onClick={() => setOpen(false)} className="gap-1.5 font-display tracking-wider text-xs">
                CLOSE
                <X className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
