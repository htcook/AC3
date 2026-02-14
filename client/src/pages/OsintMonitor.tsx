import { useState, useMemo } from 'react';
import { Link } from 'wouter';
import AppShell from "@/components/AppShell";
import { Button } from '@/components/ui/button';
import { trpc } from '@/lib/trpc';
import { toast } from 'sonner';
import {
  Radar, Plus, Globe, Shield, AlertTriangle, Bell, BellOff, CheckCircle,
  Clock, RefreshCw, Trash2, Settings, ChevronDown, ChevronUp, Loader2,
  Eye, XCircle, Server, Building, Cloud, Network, Briefcase, Play,
  Pause, BarChart3, Activity, Search, Filter
} from 'lucide-react';

const CLIENT_TYPE_ICONS: Record<string, React.ReactNode> = {
  msp: <Server className="w-3.5 h-3.5" />,
  enterprise: <Building className="w-3.5 h-3.5" />,
  saas: <Cloud className="w-3.5 h-3.5" />,
  paas: <Network className="w-3.5 h-3.5" />,
  iaas: <Server className="w-3.5 h-3.5" />,
  mixed_hosting: <Globe className="w-3.5 h-3.5" />,
  other: <Briefcase className="w-3.5 h-3.5" />,
};

const SEVERITY_STYLES: Record<string, string> = {
  info: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  warning: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
};

const INTERVAL_OPTIONS = [
  { value: 1, label: 'Every hour' },
  { value: 6, label: 'Every 6 hours' },
  { value: 12, label: 'Every 12 hours' },
  { value: 24, label: 'Daily' },
  { value: 168, label: 'Weekly' },
  { value: 720, label: 'Monthly' },
];

export default function OsintMonitor() {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [expandedMonitor, setExpandedMonitor] = useState<number | null>(null);
  const [scanningId, setScanningId] = useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Create form state
  const [newDomain, setNewDomain] = useState('');
  const [newClientType, setNewClientType] = useState<string>('enterprise');
  const [newInterval, setNewInterval] = useState(24);
  const [newNotify, setNewNotify] = useState(true);
  const [newEngagementId, setNewEngagementId] = useState<number | undefined>();
  const [isCreating, setIsCreating] = useState(false);

  // Data queries
  const { data: monitors, refetch: refetchMonitors } = trpc.monitor.list.useQuery();
  const { data: alerts, refetch: refetchAlerts } = trpc.monitor.alerts.useQuery();
  const { data: engagements } = trpc.engagements.list.useQuery();

  const createMonitor = trpc.monitor.create.useMutation();
  const deleteMonitor = trpc.monitor.delete.useMutation();
  const updateMonitor = trpc.monitor.update.useMutation();
  const scanNow = trpc.monitor.scanNow.useMutation();
  const acknowledgeChange = trpc.monitor.acknowledgeChange.useMutation();

  const filteredAlerts = useMemo(() => {
    if (!alerts) return [];
    let filtered = [...alerts];
    if (filterSeverity !== 'all') {
      filtered = filtered.filter((a: any) => a.severity === filterSeverity);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter((a: any) =>
        a.domain?.toLowerCase().includes(q) ||
        a.description?.toLowerCase().includes(q) ||
        a.changeType?.toLowerCase().includes(q)
      );
    }
    return filtered;
  }, [alerts, filterSeverity, searchQuery]);

  const handleCreate = async () => {
    if (!newDomain.trim()) { toast.error('Enter a domain'); return; }
    setIsCreating(true);
    try {
      await createMonitor.mutateAsync({
        domain: newDomain.trim(),
        clientType: newClientType as any,
        intervalHours: newInterval,
        notifyOnChange: newNotify,
        engagementId: newEngagementId,
      });
      toast.success(`Monitor created for ${newDomain}`);
      setNewDomain('');
      setShowCreateForm(false);
      refetchMonitors();
    } catch (err: any) {
      toast.error(err.message || 'Failed to create monitor');
    } finally {
      setIsCreating(false);
    }
  };

  const handleScanNow = async (id: number) => {
    setScanningId(id);
    try {
      const result = await scanNow.mutateAsync({ id });
      if (result.changes.length > 0) {
        toast.warning(`${result.changes.length} change(s) detected!`);
      } else {
        toast.success('Scan complete — no changes detected');
      }
      refetchMonitors();
      refetchAlerts();
    } catch (err: any) {
      toast.error(err.message || 'Scan failed');
    } finally {
      setScanningId(null);
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await deleteMonitor.mutateAsync({ id });
      toast.success('Monitor deleted');
      refetchMonitors();
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete');
    }
  };

  const handleToggleEnabled = async (id: number, currentEnabled: boolean) => {
    try {
      await updateMonitor.mutateAsync({ id, enabled: !currentEnabled });
      toast.success(currentEnabled ? 'Monitor paused' : 'Monitor resumed');
      refetchMonitors();
    } catch (err: any) {
      toast.error(err.message || 'Failed to update');
    }
  };

  const handleAcknowledge = async (changeId: number) => {
    try {
      await acknowledgeChange.mutateAsync({ id: changeId });
      toast.success('Alert acknowledged');
      refetchAlerts();
    } catch (err: any) {
      toast.error(err.message || 'Failed to acknowledge');
    }
  };

  const totalMonitors = monitors?.length || 0;
  const activeMonitors = monitors?.filter((m: any) => m.enabled)?.length || 0;
  const totalAlerts = alerts?.length || 0;
  const criticalAlerts = alerts?.filter((a: any) => a.severity === 'critical')?.length || 0;

  return (
    <AppShell>
      <div className="p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-xl sm:text-2xl font-display tracking-wider flex items-center gap-2">
              <Radar className="w-6 h-6 text-primary" />
              OSINT MONITOR
            </h1>
            <p className="text-sm text-muted-foreground mt-1">Recurring domain scans with change detection and alerting</p>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              className="font-display tracking-wider"
              onClick={() => { refetchMonitors(); refetchAlerts(); }}
            >
              <RefreshCw className="w-4 h-4 mr-2" /> REFRESH
            </Button>
            <Button
              size="sm"
              className="font-display tracking-wider bg-primary hover:bg-primary/90"
              onClick={() => setShowCreateForm(!showCreateForm)}
            >
              <Plus className="w-4 h-4 mr-2" /> NEW MONITOR
            </Button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-card border-2 border-border p-3 sm:p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-xs font-display tracking-wider mb-1">
              <Radar className="w-3.5 h-3.5" /> MONITORS
            </div>
            <div className="text-2xl font-display">{totalMonitors}</div>
            <div className="text-[10px] text-muted-foreground">{activeMonitors} active</div>
          </div>
          <div className="bg-card border-2 border-border p-3 sm:p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-xs font-display tracking-wider mb-1">
              <Activity className="w-3.5 h-3.5" /> ACTIVE
            </div>
            <div className="text-2xl font-display text-green-400">{activeMonitors}</div>
            <div className="text-[10px] text-muted-foreground">{totalMonitors - activeMonitors} paused</div>
          </div>
          <div className="bg-card border-2 border-border p-3 sm:p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-xs font-display tracking-wider mb-1">
              <AlertTriangle className="w-3.5 h-3.5" /> ALERTS
            </div>
            <div className="text-2xl font-display text-yellow-400">{totalAlerts}</div>
            <div className="text-[10px] text-muted-foreground">unacknowledged</div>
          </div>
          <div className="bg-card border-2 border-border p-3 sm:p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-xs font-display tracking-wider mb-1">
              <Shield className="w-3.5 h-3.5" /> CRITICAL
            </div>
            <div className="text-2xl font-display text-red-400">{criticalAlerts}</div>
            <div className="text-[10px] text-muted-foreground">require attention</div>
          </div>
        </div>

        {/* Create Monitor Form */}
        {showCreateForm && (
          <div className="bg-card border-2 border-primary/30 p-4 sm:p-6 space-y-4">
            <h2 className="font-display tracking-wider text-sm text-primary">CREATE NEW MONITOR</h2>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
              <div>
                <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">DOMAIN</label>
                <input
                  value={newDomain}
                  onChange={e => setNewDomain(e.target.value)}
                  className="w-full px-3 py-2 bg-background border-2 border-border text-sm focus:border-primary outline-none font-mono"
                  placeholder="example.com"
                />
              </div>
              <div>
                <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">CLIENT TYPE</label>
                <select
                  value={newClientType}
                  onChange={e => setNewClientType(e.target.value)}
                  className="w-full px-3 py-2 bg-background border-2 border-border text-sm focus:border-primary outline-none"
                >
                  <option value="msp">MSP</option>
                  <option value="enterprise">Enterprise</option>
                  <option value="saas">SaaS</option>
                  <option value="paas">PaaS</option>
                  <option value="iaas">IaaS</option>
                  <option value="mixed_hosting">Mixed Hosting</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">SCAN INTERVAL</label>
                <select
                  value={newInterval}
                  onChange={e => setNewInterval(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-background border-2 border-border text-sm focus:border-primary outline-none"
                >
                  {INTERVAL_OPTIONS.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">LINK TO ENGAGEMENT</label>
                <select
                  value={newEngagementId || ''}
                  onChange={e => setNewEngagementId(e.target.value ? Number(e.target.value) : undefined)}
                  className="w-full px-3 py-2 bg-background border-2 border-border text-sm focus:border-primary outline-none"
                >
                  <option value="">None (standalone)</option>
                  {engagements?.map((eng: any) => (
                    <option key={eng.id} value={eng.id}>{eng.name} — {eng.customerName}</option>
                  ))}
                </select>
              </div>
              <div className="flex items-end">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newNotify}
                    onChange={e => setNewNotify(e.target.checked)}
                    className="accent-primary"
                  />
                  <span className="text-xs font-display tracking-wider">NOTIFY ON CHANGE</span>
                </label>
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" size="sm" className="font-display tracking-wider" onClick={() => setShowCreateForm(false)}>
                CANCEL
              </Button>
              <Button
                size="sm"
                className="font-display tracking-wider bg-primary hover:bg-primary/90"
                onClick={handleCreate}
                disabled={isCreating || !newDomain.trim()}
              >
                {isCreating ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Radar className="w-4 h-4 mr-2" />}
                {isCreating ? 'SCANNING BASELINE...' : 'CREATE MONITOR'}
              </Button>
            </div>
          </div>
        )}

        {/* Active Monitors */}
        <div className="bg-card border-2 border-border p-4 sm:p-6">
          <h2 className="font-display tracking-wider text-sm text-muted-foreground mb-4">ACTIVE MONITORS</h2>
          {monitors && monitors.length > 0 ? (
            <div className="space-y-3">
              {monitors.map((monitor: any) => (
                <div key={monitor.id} className={`border-2 transition-all ${
                  expandedMonitor === monitor.id ? 'border-primary/50' : 'border-border hover:border-primary/30'
                }`}>
                  <div className="p-3 sm:p-4">
                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className={`w-2 h-2 rounded-full shrink-0 ${monitor.enabled ? 'bg-green-400 animate-pulse' : 'bg-gray-500'}`} />
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-sm font-medium">{monitor.domain}</span>
                            <span className="text-[10px] px-2 py-0.5 bg-accent/50 text-muted-foreground font-display flex items-center gap-1">
                              {CLIENT_TYPE_ICONS[monitor.clientType] || CLIENT_TYPE_ICONS.other}
                              {monitor.clientType?.toUpperCase()}
                            </span>
                            <span className="text-[10px] px-2 py-0.5 bg-accent/50 text-muted-foreground font-display">
                              {INTERVAL_OPTIONS.find(o => o.value === monitor.intervalHours)?.label || `${monitor.intervalHours}h`}
                            </span>
                            {monitor.notifyOnChange && (
                              <span title="Notifications enabled"><Bell className="w-3 h-3 text-yellow-400" /></span>
                            )}
                          </div>
                          <div className="text-xs text-muted-foreground mt-1 flex flex-wrap gap-x-3">
                            <span>Scans: {monitor.totalScans || 0}</span>
                            <span>Changes: {monitor.totalChangesDetected || 0}</span>
                            {monitor.lastScanAt && (
                              <span>Last scan: {new Date(monitor.lastScanAt).toLocaleString()}</span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-1 flex-wrap">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 text-[10px] font-display"
                          onClick={() => handleScanNow(monitor.id)}
                          disabled={scanningId === monitor.id}
                        >
                          {scanningId === monitor.id ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <><Play className="w-3.5 h-3.5 mr-1" /> SCAN NOW</>
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 text-[10px] font-display"
                          onClick={() => handleToggleEnabled(monitor.id, monitor.enabled)}
                        >
                          {monitor.enabled ? (
                            <><Pause className="w-3.5 h-3.5 mr-1" /> PAUSE</>
                          ) : (
                            <><Play className="w-3.5 h-3.5 mr-1 text-green-400" /> RESUME</>
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 text-[10px] font-display"
                          onClick={() => setExpandedMonitor(expandedMonitor === monitor.id ? null : monitor.id)}
                        >
                          {expandedMonitor === monitor.id ? (
                            <ChevronUp className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronDown className="w-3.5 h-3.5" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 text-[10px] font-display text-red-400 hover:text-red-300"
                          onClick={() => handleDelete(monitor.id)}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      </div>
                    </div>
                  </div>

                  {/* Expanded Details */}
                  {expandedMonitor === monitor.id && (
                    <MonitorDetails monitorId={monitor.id} />
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-muted-foreground">
              <Radar className="w-12 h-12 mx-auto mb-3 opacity-30" />
              <p className="font-display tracking-wider text-sm mb-1">NO MONITORS CONFIGURED</p>
              <p className="text-xs">Create a monitor to start tracking domain changes</p>
            </div>
          )}
        </div>

        {/* Alerts Panel */}
        <div className="bg-card border-2 border-border p-4 sm:p-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
            <h2 className="font-display tracking-wider text-sm text-muted-foreground flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              UNACKNOWLEDGED ALERTS ({totalAlerts})
            </h2>
            <div className="flex gap-2 flex-wrap">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <input
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="pl-8 pr-3 py-1.5 bg-background border border-border text-xs focus:border-primary outline-none w-48"
                  placeholder="Search alerts..."
                />
              </div>
              <select
                value={filterSeverity}
                onChange={e => setFilterSeverity(e.target.value)}
                className="px-2 py-1.5 bg-background border border-border text-xs focus:border-primary outline-none"
              >
                <option value="all">All Severity</option>
                <option value="critical">Critical</option>
                <option value="warning">Warning</option>
                <option value="info">Info</option>
              </select>
            </div>
          </div>

          {filteredAlerts.length > 0 ? (
            <div className="space-y-2">
              {filteredAlerts.map((alert: any) => (
                <div key={alert.id} className="border border-border p-3 hover:border-primary/30 transition-colors">
                  <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className={`text-[10px] px-2 py-0.5 font-display tracking-wider border ${SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.info}`}>
                          {alert.severity?.toUpperCase()}
                        </span>
                        <span className="font-mono text-xs">{alert.domain}</span>
                        <span className="text-[10px] px-2 py-0.5 bg-accent/50 text-muted-foreground font-display">
                          {alert.changeType?.replace(/_/g, ' ').toUpperCase()}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground">{alert.description}</p>
                      {(alert.previousValue || alert.currentValue) && (
                        <div className="mt-2 text-[10px] font-mono space-y-0.5">
                          {alert.previousValue && (
                            <div className="text-red-400/70">- {alert.previousValue}</div>
                          )}
                          {alert.currentValue && (
                            <div className="text-green-400/70">+ {alert.currentValue}</div>
                          )}
                        </div>
                      )}
                      <div className="text-[10px] text-muted-foreground mt-1">
                        {alert.createdAt && new Date(alert.createdAt).toLocaleString()}
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 text-[10px] font-display shrink-0"
                      onClick={() => handleAcknowledge(alert.id)}
                    >
                      <CheckCircle className="w-3.5 h-3.5 mr-1" /> ACK
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <CheckCircle className="w-10 h-10 mx-auto mb-2 opacity-30 text-green-400" />
              <p className="font-display tracking-wider text-sm">ALL CLEAR</p>
              <p className="text-xs">No unacknowledged alerts</p>
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}

/** Sub-component: expanded monitor details with change history */
function MonitorDetails({ monitorId }: { monitorId: number }) {
  const { data, isLoading } = trpc.monitor.get.useQuery({ id: monitorId });

  if (isLoading) {
    return (
      <div className="border-t border-border p-4 flex items-center justify-center">
        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!data) return null;

  const { monitor, changes } = data;
  const baseline = (monitor.baselineSnapshot as any) || {};

  return (
    <div className="border-t border-border p-3 sm:p-4 space-y-4 bg-background/50">
      {/* Baseline Snapshot */}
      <div>
        <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-2">BASELINE SNAPSHOT</h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2 text-xs">
          <div className="bg-card border border-border p-2">
            <div className="text-[10px] text-muted-foreground font-display">SPF</div>
            <div className="font-mono truncate text-[11px] mt-0.5">{baseline.spfRecord ? 'Configured' : 'Missing'}</div>
          </div>
          <div className="bg-card border border-border p-2">
            <div className="text-[10px] text-muted-foreground font-display">DMARC</div>
            <div className="font-mono truncate text-[11px] mt-0.5">{baseline.dmarcRecord ? 'Configured' : 'Missing'}</div>
          </div>
          <div className="bg-card border border-border p-2">
            <div className="text-[10px] text-muted-foreground font-display">DKIM</div>
            <div className="font-mono truncate text-[11px] mt-0.5">{baseline.dkimFound ? 'Found' : 'Not found'}</div>
          </div>
          <div className="bg-card border border-border p-2">
            <div className="text-[10px] text-muted-foreground font-display">MX RECORDS</div>
            <div className="font-mono truncate text-[11px] mt-0.5">{Array.isArray(baseline.mxRecords) ? baseline.mxRecords.length : 0}</div>
          </div>
          <div className="bg-card border border-border p-2">
            <div className="text-[10px] text-muted-foreground font-display">NS RECORDS</div>
            <div className="font-mono truncate text-[11px] mt-0.5">{Array.isArray(baseline.nsRecords) ? baseline.nsRecords.length : 0}</div>
          </div>
          <div className="bg-card border border-border p-2">
            <div className="text-[10px] text-muted-foreground font-display">A RECORDS</div>
            <div className="font-mono truncate text-[11px] mt-0.5">{Array.isArray(baseline.aRecords) ? baseline.aRecords.length : 0}</div>
          </div>
          <div className="bg-card border border-border p-2">
            <div className="text-[10px] text-muted-foreground font-display">SUBDOMAINS</div>
            <div className="font-mono truncate text-[11px] mt-0.5">{baseline.subdomainCount || 0}</div>
          </div>
          <div className="bg-card border border-border p-2">
            <div className="text-[10px] text-muted-foreground font-display">SPOOF SCORE</div>
            <div className={`font-mono truncate text-[11px] mt-0.5 ${
              (baseline.spoofScore || 0) > 70 ? 'text-red-400' :
              (baseline.spoofScore || 0) > 40 ? 'text-yellow-400' : 'text-green-400'
            }`}>{baseline.spoofScore || 0}/100</div>
          </div>
        </div>
        {baseline.scannedAt && (
          <div className="text-[10px] text-muted-foreground mt-2">
            Baseline captured: {new Date(baseline.scannedAt).toLocaleString()}
          </div>
        )}
      </div>

      {/* Change History */}
      <div>
        <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-2">
          CHANGE HISTORY ({changes?.length || 0})
        </h3>
        {changes && changes.length > 0 ? (
          <div className="space-y-1.5 max-h-64 overflow-y-auto">
            {changes.map((change: any) => (
              <div key={change.id} className="flex items-start gap-2 text-xs border border-border p-2 bg-card">
                <span className={`text-[10px] px-1.5 py-0.5 font-display tracking-wider border shrink-0 ${SEVERITY_STYLES[change.severity] || SEVERITY_STYLES.info}`}>
                  {change.severity?.toUpperCase()}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-display text-[10px]">{change.changeType?.replace(/_/g, ' ').toUpperCase()}</span>
                    {change.acknowledged && (
                      <span title="Acknowledged"><CheckCircle className="w-3 h-3 text-green-400" /></span>
                    )}
                  </div>
                  <p className="text-muted-foreground text-[11px] mt-0.5">{change.description}</p>
                  {(change.previousValue || change.currentValue) && (
                    <div className="mt-1 font-mono text-[10px]">
                      {change.previousValue && <div className="text-red-400/60">- {change.previousValue}</div>}
                      {change.currentValue && <div className="text-green-400/60">+ {change.currentValue}</div>}
                    </div>
                  )}
                </div>
                <span className="text-[10px] text-muted-foreground shrink-0">
                  {change.createdAt && new Date(change.createdAt).toLocaleDateString()}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-4 text-muted-foreground text-xs">
            No changes detected yet
          </div>
        )}
      </div>
    </div>
  );
}
