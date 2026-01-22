import { useState, useEffect, useRef } from 'react';
import { Link } from 'wouter';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { trpc } from '@/lib/trpc';
import {
  Activity,
  ChevronLeft,
  Play,
  Pause,
  Square,
  RefreshCw,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Shield,
  Terminal,
  Server,
  Cpu,
  Zap,
  Eye,
  Download,
  Filter
} from 'lucide-react';

const CALDERA_SERVER = '137.184.7.224';
const CALDERA_PORT = '8888';

interface AbilityResult {
  id: string;
  ability_id: string;
  ability_name: string;
  technique_id: string;
  tactic: string;
  status: 'pending' | 'running' | 'success' | 'failed' | 'blocked' | 'timeout';
  started_at: string | null;
  finished_at: string | null;
  agent_paw: string;
  agent_host: string;
  output: string;
  error_message: string | null;
  blocked_by: string | null;
  detection_details: string | null;
}

interface OperationStatus {
  id: string;
  name: string;
  adversary_id: string;
  state: 'running' | 'paused' | 'finished' | 'cleanup';
  start_time: string;
  agents: number;
  abilities_total: number;
  abilities_completed: number;
  abilities_failed: number;
  abilities_blocked: number;
}

// Simulated real-time data (in production, this would come from WebSocket)
const MOCK_OPERATION: OperationStatus = {
  id: 'databank-complete-001',
  name: 'Databank_Complete_Red_Team_Exercise',
  adversary_id: 'Databank_Complete_APT29_VCD_CrowdStrike',
  state: 'running',
  start_time: new Date().toISOString(),
  agents: 0,
  abilities_total: 59,
  abilities_completed: 0,
  abilities_failed: 0,
  abilities_blocked: 0
};

const MOCK_RESULTS: AbilityResult[] = [];

export default function OperationMonitor() {
  const [operation, setOperation] = useState<OperationStatus>(MOCK_OPERATION);
  const [results, setResults] = useState<AbilityResult[]>(MOCK_RESULTS);
  const [isConnected, setIsConnected] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState<'all' | 'success' | 'failed' | 'blocked'>('all');
  const resultsEndRef = useRef<HTMLDivElement>(null);
  
  // Fetch operations from Caldera
  const { data: operations, refetch: refetchOperations } = trpc.calderaProxy.getOperations.useQuery();

  // Poll for operation updates
  useEffect(() => {
    const pollInterval = setInterval(async () => {
      try {
        await refetchOperations();
        setIsConnected(true);
      } catch (error) {
        setIsConnected(false);
      }
    }, 5000);

    return () => clearInterval(pollInterval);
  }, [refetchOperations]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll && resultsEndRef.current) {
      resultsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [results, autoScroll]);

  const filteredResults = results.filter(r => {
    if (filter === 'all') return true;
    if (filter === 'success') return r.status === 'success';
    if (filter === 'failed') return r.status === 'failed' || r.status === 'timeout';
    if (filter === 'blocked') return r.status === 'blocked';
    return true;
  });

  const getStatusIcon = (status: AbilityResult['status']) => {
    switch (status) {
      case 'success': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed': return <XCircle className="w-4 h-4 text-red-500" />;
      case 'blocked': return <Shield className="w-4 h-4 text-yellow-500" />;
      case 'running': return <Activity className="w-4 h-4 text-blue-500 animate-pulse" />;
      case 'timeout': return <Clock className="w-4 h-4 text-orange-500" />;
      default: return <Clock className="w-4 h-4 text-muted-foreground" />;
    }
  };

  const getStatusBadge = (status: AbilityResult['status']) => {
    const variants: Record<string, string> = {
      success: 'bg-green-500/20 text-green-500 border-green-500',
      failed: 'bg-red-500/20 text-red-500 border-red-500',
      blocked: 'bg-yellow-500/20 text-yellow-500 border-yellow-500',
      running: 'bg-blue-500/20 text-blue-500 border-blue-500',
      timeout: 'bg-orange-500/20 text-orange-500 border-orange-500',
      pending: 'bg-gray-500/20 text-gray-500 border-gray-500'
    };
    return variants[status] || variants.pending;
  };

  const formatDuration = (start: string | null, end: string | null) => {
    if (!start) return '-';
    const startTime = new Date(start).getTime();
    const endTime = end ? new Date(end).getTime() : Date.now();
    const duration = Math.round((endTime - startTime) / 1000);
    if (duration < 60) return `${duration}s`;
    return `${Math.floor(duration / 60)}m ${duration % 60}s`;
  };

  const exportResults = () => {
    const exportData = {
      operation: operation,
      results: results,
      exported_at: new Date().toISOString(),
      summary: {
        total: results.length,
        success: results.filter(r => r.status === 'success').length,
        failed: results.filter(r => r.status === 'failed').length,
        blocked: results.filter(r => r.status === 'blocked').length,
        timeout: results.filter(r => r.status === 'timeout').length
      }
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `operation_results_${operation.id}_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="border-b border-border bg-card sticky top-0 z-10">
        <div className="container py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link href="/dashboard">
                <Button variant="ghost" size="sm" className="font-display">
                  <ChevronLeft className="w-4 h-4 mr-1" />
                  DASHBOARD
                </Button>
              </Link>
              <div className="h-6 w-px bg-border" />
              <div className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-primary" />
                <h1 className="font-display text-xl tracking-wider">OPERATION MONITOR</h1>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                <span className="text-xs text-muted-foreground">
                  {isConnected ? 'CONNECTED' : 'DISCONNECTED'}
                </span>
              </div>
              <Button variant="outline" size="sm" onClick={exportResults}>
                <Download className="w-4 h-4 mr-1" />
                Export
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="container py-6">
        {/* Operation Status Card */}
        <div className="bg-card border-2 border-primary mb-6">
          <div className="p-4 border-b border-border">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="font-display text-lg">{operation.name}</h2>
                <p className="text-sm text-muted-foreground">Adversary: {operation.adversary_id}</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge className={`${
                  operation.state === 'running' ? 'bg-green-500' :
                  operation.state === 'paused' ? 'bg-yellow-500' :
                  operation.state === 'finished' ? 'bg-blue-500' : 'bg-gray-500'
                }`}>
                  {operation.state.toUpperCase()}
                </Badge>
                <div className="flex gap-1">
                  <Button size="sm" variant="ghost" disabled={operation.state === 'running'}>
                    <Play className="w-4 h-4" />
                  </Button>
                  <Button size="sm" variant="ghost" disabled={operation.state !== 'running'}>
                    <Pause className="w-4 h-4" />
                  </Button>
                  <Button size="sm" variant="ghost">
                    <Square className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            </div>
          </div>
          
          {/* Stats Row */}
          <div className="grid grid-cols-6 divide-x divide-border">
            <div className="p-4 text-center">
              <div className="text-2xl font-bold text-primary">{operation.agents}</div>
              <div className="text-xs text-muted-foreground">AGENTS</div>
            </div>
            <div className="p-4 text-center">
              <div className="text-2xl font-bold">{operation.abilities_total}</div>
              <div className="text-xs text-muted-foreground">TOTAL</div>
            </div>
            <div className="p-4 text-center">
              <div className="text-2xl font-bold text-green-500">{operation.abilities_completed}</div>
              <div className="text-xs text-muted-foreground">SUCCESS</div>
            </div>
            <div className="p-4 text-center">
              <div className="text-2xl font-bold text-red-500">{operation.abilities_failed}</div>
              <div className="text-xs text-muted-foreground">FAILED</div>
            </div>
            <div className="p-4 text-center">
              <div className="text-2xl font-bold text-yellow-500">{operation.abilities_blocked}</div>
              <div className="text-xs text-muted-foreground">BLOCKED</div>
            </div>
            <div className="p-4 text-center">
              <div className="text-2xl font-bold">
                {operation.abilities_total > 0 
                  ? Math.round((operation.abilities_completed / operation.abilities_total) * 100)
                  : 0}%
              </div>
              <div className="text-xs text-muted-foreground">PROGRESS</div>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="h-2 bg-secondary">
            <div 
              className="h-full bg-gradient-to-r from-green-500 via-yellow-500 to-red-500 transition-all duration-500"
              style={{ 
                width: `${operation.abilities_total > 0 
                  ? ((operation.abilities_completed + operation.abilities_failed + operation.abilities_blocked) / operation.abilities_total) * 100 
                  : 0}%` 
              }}
            />
          </div>
        </div>

        {/* Live Operations from Caldera */}
        {operations && operations.length > 0 && (
          <div className="bg-card border-2 border-border mb-6">
            <div className="p-4 border-b border-border">
              <h3 className="font-display">CALDERA OPERATIONS</h3>
            </div>
            <div className="divide-y divide-border">
              {operations.map((op: any) => (
                <div key={op.id} className="p-4 flex items-center justify-between">
                  <div>
                    <div className="font-medium">{op.name}</div>
                    <div className="text-sm text-muted-foreground">
                      Adversary: {op.adversary?.name || op.adversary_id || 'N/A'}
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <Badge className={`${
                      op.state === 'running' ? 'bg-green-500' :
                      op.state === 'paused' ? 'bg-yellow-500' :
                      op.state === 'finished' ? 'bg-blue-500' : 'bg-gray-500'
                    }`}>
                      {op.state?.toUpperCase() || 'UNKNOWN'}
                    </Badge>
                    <a 
                      href={`http://${CALDERA_SERVER}:${CALDERA_PORT}/operations/${op.id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <Button size="sm" variant="outline">
                        <Eye className="w-4 h-4 mr-1" />
                        View in Caldera
                      </Button>
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Results Filter */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">Filter:</span>
            <div className="flex gap-1">
              {(['all', 'success', 'failed', 'blocked'] as const).map(f => (
                <Button
                  key={f}
                  size="sm"
                  variant={filter === f ? 'default' : 'ghost'}
                  onClick={() => setFilter(f)}
                  className="text-xs"
                >
                  {f.toUpperCase()}
                </Button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant={autoScroll ? 'default' : 'ghost'}
              onClick={() => setAutoScroll(!autoScroll)}
            >
              Auto-scroll {autoScroll ? 'ON' : 'OFF'}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => refetchOperations()}>
              <RefreshCw className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {/* Results Timeline */}
        <div className="bg-card border-2 border-border">
          <div className="p-4 border-b border-border bg-secondary/30">
            <div className="grid grid-cols-12 gap-4 text-xs font-display text-muted-foreground">
              <div className="col-span-1">STATUS</div>
              <div className="col-span-3">ABILITY</div>
              <div className="col-span-2">TECHNIQUE</div>
              <div className="col-span-2">AGENT</div>
              <div className="col-span-1">DURATION</div>
              <div className="col-span-3">DETAILS</div>
            </div>
          </div>

          <div className="max-h-[500px] overflow-y-auto">
            {filteredResults.length === 0 ? (
              <div className="p-12 text-center">
                <Activity className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="font-display text-lg mb-2">NO RESULTS YET</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Deploy agents and start the operation to see real-time results here.
                </p>
                <div className="flex justify-center gap-2">
                  <Link href="/agents/deploy">
                    <Button size="sm">
                      <Terminal className="w-4 h-4 mr-1" />
                      Deploy Agents
                    </Button>
                  </Link>
                  <a href={`http://${CALDERA_SERVER}:${CALDERA_PORT}`} target="_blank" rel="noopener noreferrer">
                    <Button size="sm" variant="outline">
                      <Zap className="w-4 h-4 mr-1" />
                      Open Caldera
                    </Button>
                  </a>
                </div>
              </div>
            ) : (
              <div className="divide-y divide-border">
                {filteredResults.map((result, index) => (
                  <div 
                    key={result.id || index}
                    className={`p-4 hover:bg-secondary/30 transition-colors ${
                      result.status === 'blocked' ? 'bg-yellow-500/5' :
                      result.status === 'failed' ? 'bg-red-500/5' : ''
                    }`}
                  >
                    <div className="grid grid-cols-12 gap-4 items-start">
                      <div className="col-span-1">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(result.status)}
                          <Badge className={`text-xs ${getStatusBadge(result.status)}`}>
                            {result.status.toUpperCase()}
                          </Badge>
                        </div>
                      </div>
                      <div className="col-span-3">
                        <div className="font-medium text-sm">{result.ability_name}</div>
                        <div className="text-xs text-muted-foreground">{result.tactic}</div>
                      </div>
                      <div className="col-span-2">
                        <a 
                          href={`https://attack.mitre.org/techniques/${result.technique_id?.replace('.', '/')}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary hover:underline text-sm"
                        >
                          {result.technique_id}
                        </a>
                      </div>
                      <div className="col-span-2">
                        <div className="flex items-center gap-1 text-sm">
                          <Cpu className="w-3 h-3" />
                          {result.agent_host || 'N/A'}
                        </div>
                        <div className="text-xs text-muted-foreground">{result.agent_paw}</div>
                      </div>
                      <div className="col-span-1 text-sm">
                        {formatDuration(result.started_at, result.finished_at)}
                      </div>
                      <div className="col-span-3">
                        {result.status === 'blocked' && result.blocked_by && (
                          <div className="text-xs bg-yellow-500/20 text-yellow-500 p-2 rounded">
                            <div className="font-semibold">Blocked by: {result.blocked_by}</div>
                            {result.detection_details && (
                              <div className="mt-1">{result.detection_details}</div>
                            )}
                          </div>
                        )}
                        {result.status === 'failed' && result.error_message && (
                          <div className="text-xs bg-red-500/20 text-red-500 p-2 rounded">
                            {result.error_message}
                          </div>
                        )}
                        {result.status === 'success' && result.output && (
                          <div className="text-xs text-muted-foreground truncate">
                            {result.output.substring(0, 100)}...
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
                <div ref={resultsEndRef} />
              </div>
            )}
          </div>
        </div>

        {/* Security Control Effectiveness Summary */}
        {results.length > 0 && (
          <div className="mt-6 bg-card border-2 border-border">
            <div className="p-4 border-b border-border">
              <h3 className="font-display">SECURITY CONTROL EFFECTIVENESS</h3>
            </div>
            <div className="p-4">
              <div className="grid grid-cols-3 gap-6">
                <div>
                  <h4 className="text-sm font-display text-muted-foreground mb-2">DETECTION RATE</h4>
                  <div className="text-3xl font-bold text-yellow-500">
                    {results.length > 0 
                      ? Math.round((results.filter(r => r.status === 'blocked').length / results.length) * 100)
                      : 0}%
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {results.filter(r => r.status === 'blocked').length} of {results.length} abilities detected
                  </p>
                </div>
                <div>
                  <h4 className="text-sm font-display text-muted-foreground mb-2">PREVENTION RATE</h4>
                  <div className="text-3xl font-bold text-green-500">
                    {results.length > 0 
                      ? Math.round(((results.filter(r => r.status === 'blocked' || r.status === 'failed').length) / results.length) * 100)
                      : 0}%
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {results.filter(r => r.status === 'blocked' || r.status === 'failed').length} abilities prevented
                  </p>
                </div>
                <div>
                  <h4 className="text-sm font-display text-muted-foreground mb-2">SUCCESSFUL ATTACKS</h4>
                  <div className="text-3xl font-bold text-red-500">
                    {results.filter(r => r.status === 'success').length}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    Abilities that bypassed controls
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
