import { lazy, Suspense, useState } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger
} from "@/components/ui/dropdown-menu";
import { ChevronDown, Shield, Terminal, BarChart3, Users, Eye, Settings, LayoutDashboard, ArrowRight } from "lucide-react";

const OperatorHome = lazy(() => import("./OperatorHome"));
const ExecutiveHome = lazy(() => import("./ExecutiveHome"));
const AnalystHome = lazy(() => import("./AnalystHome"));
const TeamLeadHome = lazy(() => import("./TeamLeadHome"));
const ClientHome = lazy(() => import("./ClientHome"));
const AdminHome = lazy(() => import("./AdminHome"));

const ROLE_DASHBOARDS: Record<string, {
  component: React.LazyExoticComponent<() => JSX.Element>;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}> = {
  operator: { component: OperatorHome, label: "OPERATOR", icon: Terminal },
  executive: { component: ExecutiveHome, label: "EXECUTIVE", icon: BarChart3 },
  analyst: { component: AnalystHome, label: "ANALYST", icon: Eye },
  team_lead: { component: TeamLeadHome, label: "TEAM LEAD", icon: Users },
  client: { component: ClientHome, label: "CLIENT", icon: Shield },
  admin: { component: AdminHome, label: "ADMIN", icon: Settings },
};

function DashboardSkeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="h-8 w-64 bg-secondary rounded" />
      <div className="h-4 w-96 bg-secondary/50 rounded" />
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-28 bg-secondary/30 rounded-lg" />
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="h-64 bg-secondary/30 rounded-lg" />
        <div className="h-64 bg-secondary/30 rounded-lg" />
      </div>
    </div>
  );
}

export default function RoleHome() {
  // Use Caldera auth session (not Manus OAuth) for role detection
  const { data: session } = trpc.calderaAuth.session.useQuery();
  const userRole = session?.authenticated ? (session.user?.role as string || "operator") : "operator";
  const [previewRole, setPreviewRole] = useState<string | null>(null);

  const activeRole = previewRole || userRole;
  const dashboard = ROLE_DASHBOARDS[activeRole] || ROLE_DASHBOARDS.operator;
  const DashboardComponent = dashboard.component;
  const isAdmin = userRole === "admin";
  const isPreviewing = previewRole !== null && previewRole !== userRole;

  return (
    <div className="space-y-4">
      {/* Navigation bar with link to main dashboard */}
      <div className="flex items-center justify-between px-1">
        <div className="flex items-center gap-3">
          <Link href="/dashboard">
            <Button variant="outline" size="sm" className="text-[10px] font-display tracking-wider h-7 gap-1.5 hover:bg-primary/10">
              <LayoutDashboard className="w-3 h-3" />
              MAIN DASHBOARD
              <ArrowRight className="w-3 h-3" />
            </Button>
          </Link>
          {isPreviewing && (
            <span className="text-[9px] font-display tracking-widest text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-1 rounded">
              PREVIEW MODE
            </span>
          )}
        </div>

        {/* Role Switcher - only visible to admins */}
        {isAdmin && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="text-[10px] font-display tracking-wider h-7 gap-1">
                <dashboard.icon className="w-3 h-3" />
                {dashboard.label} VIEW
                <ChevronDown className="w-3 h-3" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {Object.entries(ROLE_DASHBOARDS).map(([role, config]) => (
                <DropdownMenuItem
                  key={role}
                  onClick={() => setPreviewRole(role === userRole ? null : role)}
                  className="text-xs font-display tracking-wider gap-2"
                >
                  <config.icon className="w-3.5 h-3.5" />
                  {config.label}
                  {role === userRole && <span className="text-[9px] text-muted-foreground ml-auto">(YOUR ROLE)</span>}
                  {role === activeRole && <span className="text-[9px] text-primary ml-auto">ACTIVE</span>}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>

      {/* Render the active dashboard */}
      <Suspense fallback={<DashboardSkeleton />}>
        <DashboardComponent />
      </Suspense>
    </div>
  );
}
