import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { 
  Cloud, 
  Activity, 
  Key,
  Users,
  LogOut,
  Menu,
  X,
  Target,
  FileText,
  Plus,
  Play,
  Pause,
  CheckCircle,
  Clock,
  Crosshair,
  ChevronRight,
  Zap,
  Cpu,
  ExternalLink,
  AlertTriangle,
  RefreshCw,
  BookOpen,
  Shield,
  Globe2,
  Briefcase,
} from "lucide-react";
import { useState, useMemo } from "react";

import AppShell from "@/components/AppShell";
const STATUS_STYLES: Record<string, { bg: string; text: string; icon: React.ReactNode }> = {
  paused: { bg: 'bg-yellow-500/20 border-yellow-500', text: 'text-yellow-400', icon: <Pause className="w-4 h-4" /> },
  running: { bg: 'bg-green-500/20 border-green-500', text: 'text-green-400', icon: <Play className="w-4 h-4" /> },
  finished: { bg: 'bg-blue-500/20 border-blue-500', text: 'text-blue-400', icon: <CheckCircle className="w-4 h-4" /> },
  cleanup: { bg: 'bg-orange-500/20 border-orange-500', text: 'text-orange-400', icon: <AlertTriangle className="w-4 h-4" /> },
};

// Predefined operation metadata for enhanced display
const OPERATION_METADATA: Record<string, { description: string; targetEnvironment: string; tags: string[] }> = {
  'MSP_Target_Complete_Red_Team_Exercise': {
    description: 'Comprehensive red team exercise combining APT29 VCD Cloud Compromise techniques with CrowdStrike Falcon bypass capabilities. Covers full attack lifecycle from reconnaissance to impact.',
    targetEnvironment: 'VMware Cloud Director + Windows Endpoints',
    tags: ['APT29', 'VCD', 'CROWDSTRIKE BYPASS', 'FULL LIFECYCLE'],
  },
  'APT29_VCD_Red_Team_Exercise': {
    description: 'Enhanced campaign for VMware Cloud Director environments with authentic APT29 TTPs. Focuses on cloud infrastructure compromise and data exfiltration.',
    targetEnvironment: 'VMware Cloud Director (VCD)',
    tags: ['APT29', 'CLOUD', 'VCD', 'EXFILTRATION'],
  },
  'CrowdStrike_Falcon_Bypass_Operation': {
    description: 'Defense evasion operation specifically designed for testing CrowdStrike Falcon-protected endpoints. Includes EDR bypass and stealth techniques.',
    targetEnvironment: 'Windows Endpoints with CrowdStrike',
    tags: ['EDR BYPASS', 'T1562.001', 'STEALTH', 'DEFENSE EVASION'],
  },
};

export default function Campaigns() {
  const [, navigate] = useLocation();

  // Fetch live operations from the emulation framework
  const { data: operations, isLoading, refetch, isRefetching } = trpc.calderaProxy.getOperations.useQuery();
  const { data: allAbilities } = trpc.calderaProxy.getAbilities.useQuery();

  // Create ability map for quick lookup
  const abilityMap = useMemo(() => {
    if (!allAbilities) return new Map();
    return new Map(allAbilities.map((a: any) => [a.ability_id, a]));
  }, [allAbilities]);

  // Enrich operations with metadata
  const enrichedOperations = useMemo(() => {
    if (!operations) return [];
    return operations.map((op: any) => {
      const metadata = OPERATION_METADATA[op.name] || {
        description: op.adversary?.description || 'Red team operation',
        targetEnvironment: 'Target Environment',
        tags: [],
      };
      const abilities = op.adversary?.atomic_ordering || [];
      return {
        ...op,
        ...metadata,
        abilityCount: abilities.length,
      };
    });
  }, [operations]);

  const handleOpenCaldera = () => {
    window.open('https://caldera.aceofcloud.io', '_blank');
  };

  const handleRefresh = () => {
    refetch();
    toast.success('Refreshing operations from emulation framework...');
  };

  return (
    <AppShell activePath="/campaigns">
{/* Sidebar */}
<header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4 flex items-center justify-between">
            <div>
              <h1 className="font-display text-3xl md:text-2xl sm:text-3xl lg:text-4xl">CAMPAIGNS & OPERATIONS</h1>
              <p className="text-sm text-muted-foreground">Red team exercise campaigns with full ability details</p>
            </div>
            <div className="flex gap-2">
              <Button 
                variant="outline"
                className="font-display tracking-wider"
                onClick={handleRefresh}
                disabled={isRefetching}
              >
                <RefreshCw className={`w-4 h-4 mr-2 ${isRefetching ? 'animate-spin' : ''}`} />
                REFRESH
              </Button>
              <Button 
                className="font-display tracking-wider bg-primary hover:bg-primary/90"
                onClick={handleOpenCaldera}
              >
                <ExternalLink className="w-4 h-4 mr-2" />
                OPEN CALDERA
              </Button>
            </div>
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">
          {/* Stats Summary */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-card border-2 border-border p-4">
              <div className="flex items-center gap-2 text-muted-foreground mb-2">
                <Crosshair className="w-4 h-4" />
                <span className="text-xs uppercase">Total Operations</span>
              </div>
              <p className="font-display text-3xl text-primary">{enrichedOperations.length}</p>
            </div>
            <div className="bg-card border-2 border-border p-4">
              <div className="flex items-center gap-2 text-muted-foreground mb-2">
                <Zap className="w-4 h-4" />
                <span className="text-xs uppercase">Total Abilities</span>
              </div>
              <p className="font-display text-3xl text-primary">
                {enrichedOperations.reduce((sum: number, op: any) => sum + op.abilityCount, 0)}
              </p>
            </div>
            <div className="bg-card border-2 border-border p-4">
              <div className="flex items-center gap-2 text-muted-foreground mb-2">
                <Play className="w-4 h-4" />
                <span className="text-xs uppercase">Running</span>
              </div>
              <p className="font-display text-3xl text-green-400">
                {enrichedOperations.filter((op: any) => op.state === 'running').length}
              </p>
            </div>
          </div>

          {/* Loading State */}
          {isLoading && (
            <div className="flex items-center justify-center py-12">
              <div className="text-center">
                <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full mx-auto mb-4" />
                <p className="text-muted-foreground">Loading operations from the emulation framework...</p>
              </div>
            </div>
          )}

          {/* No Operations */}
          {!isLoading && enrichedOperations.length === 0 && (
            <div className="bg-card border-2 border-border p-4 sm:p-6 lg:p-8 text-center">
              <AlertTriangle className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
              <h3 className="font-display text-xl mb-2">No Operations Found</h3>
              <p className="text-muted-foreground mb-4">
                Create operations in the emulation framework to see them here.
              </p>
              <Button onClick={handleOpenCaldera}>
                <ExternalLink className="w-4 h-4 mr-2" />
                Open Emulation UI
              </Button>
            </div>
          )}

          {/* Operation List */}
          {!isLoading && enrichedOperations.length > 0 && (
            <div className="grid gap-4">
              {enrichedOperations.map((operation: any) => {
                const statusStyle = STATUS_STYLES[operation.state] || STATUS_STYLES.paused;
                return (
                  <Link key={operation.id} href={`/operations/${operation.id}`}>
                    <div className="bg-card border-2 border-border hover:border-primary transition-colors p-6 cursor-pointer">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-3 mb-2 flex-wrap">
                            <Crosshair className="w-5 h-5 text-primary flex-shrink-0" />
                            <h3 className="font-display text-xl">{operation.name}</h3>
                            <span className={`px-2 py-1 text-xs font-display border ${statusStyle.bg} ${statusStyle.text} flex items-center gap-1`}>
                              {statusStyle.icon}
                              {operation.state.toUpperCase()}
                            </span>
                            <span className="px-2 py-1 text-xs font-display bg-primary/20 text-primary border border-primary">
                              {operation.abilityCount} ABILITIES
                            </span>
                          </div>
                          {operation.description && (
                            <p className="text-sm text-muted-foreground mb-3 line-clamp-2">{operation.description}</p>
                          )}
                          <div className="flex flex-wrap gap-2 mb-3">
                            {operation.tags?.map((tag: string) => (
                              <span key={tag} className="px-2 py-1 text-xs bg-secondary text-muted-foreground">
                                {tag}
                              </span>
                            ))}
                          </div>
                          <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                            {operation.adversary?.name && (
                              <span className="flex items-center gap-1">
                                <Target className="w-3 h-3" />
                                {operation.adversary.name}
                              </span>
                            )}
                            {operation.targetEnvironment && (
                              <span className="flex items-center gap-1">
                                <Zap className="w-3 h-3" />
                                {operation.targetEnvironment}
                              </span>
                            )}
                            <span className="flex items-center gap-1">
                              <Cpu className="w-3 h-3" />
                              {operation.host_group?.length || 0} Agents
                            </span>
                          </div>
                        </div>
                        <ChevronRight className="w-5 h-5 text-muted-foreground flex-shrink-0" />
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}

          {/* Info Banner */}
          <div className="bg-blue-500/10 border-2 border-blue-500/30 p-4">
            <p className="text-sm text-blue-400">
              <strong>Tip:</strong> Click on any operation to view all abilities with MITRE ATT&CK mapping. 
              Operations are synced live from the emulation server at caldera.aceofcloud.io.
            </p>
          </div>
        </div>
    </AppShell>
  );
}

