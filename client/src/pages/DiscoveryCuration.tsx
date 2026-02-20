import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useParams, useLocation } from "wouter";
import { toast } from "sonner";
import {
  Globe, Shield, Server, AlertTriangle, Eye, EyeOff, Trash2, Undo2,
  CheckCircle2, XCircle, Filter, Search, ChevronDown, ChevronRight,
  ExternalLink, ArrowRight, Loader2, Info, Ban, RotateCcw, Check,
  X, Building2, Cpu, Mail, Cloud, Lock, Zap, Layers, BarChart3,
  FileText, Copy, Download
} from "lucide-react";
import { useState, useMemo, useCallback } from "react";
import AppShell from "@/components/AppShell";

import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
type ExclusionReason = 'wrong_company' | 'outdated' | 'duplicate' | 'irrelevant' | 'false_positive' | 'custom';

const EXCLUSION_REASONS: { value: ExclusionReason; label: string; desc: string }[] = [
  { value: 'wrong_company', label: 'Wrong Company/Org', desc: 'This asset belongs to a different organization' },
  { value: 'outdated', label: 'Outdated / Decommissioned', desc: 'This asset no longer exists or is not in use' },
  { value: 'duplicate', label: 'Duplicate Entry', desc: 'This is a duplicate of another discovered asset' },
  { value: 'irrelevant', label: 'Not Relevant', desc: 'This asset is not relevant to the engagement scope' },
  { value: 'false_positive', label: 'False Positive', desc: 'This was incorrectly identified by the scanner' },
  { value: 'custom', label: 'Other Reason', desc: 'Provide a custom reason' },
];

const RISK_COLORS: Record<string, string> = {
  critical: 'text-red-500 bg-red-500/10 border-red-500/30',
  high: 'text-orange-500 bg-orange-500/10 border-orange-500/30',
  medium: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30',
  low: 'text-green-500 bg-green-500/10 border-green-500/30',
};

const ASSET_TYPE_ICONS: Record<string, React.ReactNode> = {
  sso: <Lock className="w-4 h-4" />,
  mail_gateway: <Mail className="w-4 h-4" />,
  api: <Cpu className="w-4 h-4" />,
  cdn: <Cloud className="w-4 h-4" />,
  web: <Globe className="w-4 h-4" />,
  payment: <BarChart3 className="w-4 h-4" />,
  dns: <Server className="w-4 h-4" />,
};

export default function DiscoveryCuration() {
  const params = useParams<{ scanId: string }>();
  const scanId = parseInt(params.scanId || '0');
  const [, navigate] = useLocation();

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [showExcluded, setShowExcluded] = useState(false);
  const [riskFilter, setRiskFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [confidenceFilter, setConfidenceFilter] = useState<string>('all');

  // Selection
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [bulkExcludeOpen, setBulkExcludeOpen] = useState(false);
  const [bulkReason, setBulkReason] = useState<ExclusionReason>('wrong_company');
  const [bulkCustomReason, setBulkCustomReason] = useState('');

  // Single exclude dialog
  const [excludeDialogAssetId, setExcludeDialogAssetId] = useState<number | null>(null);
  const [excludeReason, setExcludeReason] = useState<ExclusionReason>('wrong_company');
  const [excludeCustomReason, setExcludeCustomReason] = useState('');

  // Expanded asset detail
  const [expandedAssetId, setExpandedAssetId] = useState<number | null>(null);

  // Data
  const { data: scanData, isLoading: scanLoading } = trpc.domainIntel.getScan.useQuery(
    { id: scanId },
    { enabled: scanId > 0 }
  );
  const { data: assets, isLoading: assetsLoading, refetch: refetchAssets } = trpc.domainIntel.getAssets.useQuery(
    { scanId },
    { enabled: scanId > 0 }
  );

  const utils = trpc.useUtils();

  // Mutations
  const excludeAsset = trpc.domainIntel.excludeAsset.useMutation({
    onSuccess: () => {
      toast.success('Asset excluded from engagement scope');
      refetchAssets();
      setExcludeDialogAssetId(null);
    },
    onError: (err) => toast.error(`Failed: ${sanitizeErrorForToast(err)}`),
  });

  const includeAsset = trpc.domainIntel.includeAsset.useMutation({
    onSuccess: () => {
      toast.success('Asset restored to engagement scope');
      refetchAssets();
    },
    onError: (err) => toast.error(`Failed: ${sanitizeErrorForToast(err)}`),
  });

  const bulkExclude = trpc.domainIntel.bulkExcludeAssets.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.count} assets excluded`);
      refetchAssets();
      setSelectedIds(new Set());
      setBulkExcludeOpen(false);
    },
    onError: (err) => toast.error(`Failed: ${sanitizeErrorForToast(err)}`),
  });

  const bulkInclude = trpc.domainIntel.bulkIncludeAssets.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.count} assets restored`);
      refetchAssets();
      setSelectedIds(new Set());
    },
    onError: (err) => toast.error(`Failed: ${sanitizeErrorForToast(err)}`),
  });

  // Filtered assets
  const filteredAssets = useMemo(() => {
    if (!assets) return [];
    return assets.filter((a: any) => {
      // Show/hide excluded
      if (!showExcluded && a.excluded) return false;
      if (showExcluded && !a.excluded) return false;

      // Search
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchesSearch =
          a.hostname?.toLowerCase().includes(q) ||
          a.url?.toLowerCase().includes(q) ||
          a.assetType?.toLowerCase().includes(q) ||
          (a.technologies as any[])?.some((t: string) => t.toLowerCase().includes(q)) ||
          (a.tags as any[])?.some((t: string) => t.toLowerCase().includes(q));
        if (!matchesSearch) return false;
      }

      // Risk filter
      if (riskFilter !== 'all' && a.riskBand !== riskFilter) return false;

      // Type filter
      if (typeFilter !== 'all' && a.assetType !== typeFilter) return false;

      // Confidence filter
      if (confidenceFilter !== 'all') {
        const conf = a.confidence || 0;
        if (confidenceFilter === 'high' && conf < 80) return false;
        if (confidenceFilter === 'medium' && (conf < 50 || conf >= 80)) return false;
        if (confidenceFilter === 'low' && conf >= 50) return false;
      }

      return true;
    });
  }, [assets, showExcluded, searchQuery, riskFilter, typeFilter, confidenceFilter]);

  // Stats
  const stats = useMemo(() => {
    if (!assets) return { total: 0, included: 0, excluded: 0, critical: 0, high: 0, medium: 0, low: 0 };
    const included = assets.filter((a: any) => !a.excluded);
    const excluded = assets.filter((a: any) => a.excluded);
    return {
      total: assets.length,
      included: included.length,
      excluded: excluded.length,
      critical: included.filter((a: any) => a.riskBand === 'critical').length,
      high: included.filter((a: any) => a.riskBand === 'high').length,
      medium: included.filter((a: any) => a.riskBand === 'medium').length,
      low: included.filter((a: any) => a.riskBand === 'low').length,
    };
  }, [assets]);

  // Asset types for filter
  const assetTypes = useMemo(() => {
    if (!assets) return [];
    const types = new Set(assets.map((a: any) => a.assetType).filter(Boolean));
    return Array.from(types) as string[];
  }, [assets]);

  // Selection helpers
  const toggleSelect = (id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    setSelectedIds(new Set(filteredAssets.map((a: any) => a.id)));
  };

  const selectNone = () => setSelectedIds(new Set());

  const handleExclude = (assetId: number) => {
    const reason = excludeReason === 'custom' ? excludeCustomReason : EXCLUSION_REASONS.find(r => r.value === excludeReason)?.label || excludeReason;
    if (!reason.trim()) {
      toast.error('Please provide a reason');
      return;
    }
    excludeAsset.mutate({ assetId, reason });
  };

  const handleBulkExclude = () => {
    const reason = bulkReason === 'custom' ? bulkCustomReason : EXCLUSION_REASONS.find(r => r.value === bulkReason)?.label || bulkReason;
    if (!reason.trim()) {
      toast.error('Please provide a reason');
      return;
    }
    bulkExclude.mutate({ assetIds: Array.from(selectedIds), reason });
  };

  const scan = scanData?.scan;
  const pipelineOutput = scan?.pipelineOutput as any;
  const riskScore = pipelineOutput?.riskScore || 0;

  if (scanLoading || assetsLoading) {
    return (
      <AppShell activePath="/domain-intel">
        <div className="flex items-center justify-center h-96">
          <Loader2 className="w-8 h-8 text-primary animate-spin" />
        </div>
      </AppShell>
    );
  }

  if (!scan) {
    return (
      <AppShell activePath="/domain-intel">
        <div className="flex flex-col items-center justify-center h-96 gap-4">
          <AlertTriangle className="w-12 h-12 text-yellow-500" />
          <p className="text-muted-foreground">Scan not found</p>
          <Link href="/domain-intel">
            <Button variant="outline">Back to Domain Intel</Button>
          </Link>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell activePath="/domain-intel">
      <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="px-4 sm:px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href={`/domain-intel/${scanId}`}>
              <Button variant="ghost" size="sm" className="font-display tracking-wider text-xs">
                <ChevronRight className="w-3 h-3 mr-1 rotate-180" /> BACK TO RESULTS
              </Button>
            </Link>
            <div className="w-px h-6 bg-border" />
            <div>
              <h1 className="font-display text-xl sm:text-2xl tracking-wider">DISCOVERY CURATION</h1>
              <p className="text-xs text-muted-foreground">Review, verify, and remove incorrect findings before campaign generation</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="font-display tracking-wider text-xs"
              onClick={() => navigate(`/domain-intel/${scanId}`)}
            >
              <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
              CONFIRM & PROCEED
            </Button>
          </div>
        </div>
        <div className="w-full h-1 bg-gradient-to-r from-cyan-500 via-primary to-emerald-500" />
      </header>

      <div className="p-4 sm:p-6 space-y-5">

        {/* ═══ SCAN CONTEXT ═══ */}
        <div className="bg-card border border-border p-4 flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <Globe className="w-5 h-5 text-cyan-400" />
            <span className="font-mono text-lg">{scan.primaryDomain}</span>
          </div>
          <div className="w-px h-6 bg-border" />
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] font-display tracking-wider text-muted-foreground">RISK SCORE</span>
            <span className={`font-display text-xl ${riskScore >= 80 ? 'text-red-500' : riskScore >= 60 ? 'text-orange-500' : riskScore >= 40 ? 'text-yellow-500' : 'text-green-500'}`}>
              {riskScore}
            </span>
          </div>
          <div className="w-px h-6 bg-border" />
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] font-display tracking-wider text-muted-foreground">TYPE</span>
            <span className="text-xs">{scan.clientType?.toUpperCase()}</span>
          </div>
          {scan.sector && (
            <>
              <div className="w-px h-6 bg-border" />
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] font-display tracking-wider text-muted-foreground">SECTOR</span>
                <span className="text-xs">{scan.sector}</span>
              </div>
            </>
          )}
        </div>

        {/* ═══ CURATION STATS ═══ */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
          <StatCard value={stats.total} label="TOTAL FOUND" color="text-foreground" />
          <StatCard value={stats.included} label="INCLUDED" color="text-green-500" active={!showExcluded} onClick={() => setShowExcluded(false)} />
          <StatCard value={stats.excluded} label="EXCLUDED" color="text-red-500" active={showExcluded} onClick={() => setShowExcluded(true)} />
          <StatCard value={stats.critical} label="CRITICAL" color="text-red-500" />
          <StatCard value={stats.high} label="HIGH" color="text-orange-500" />
          <StatCard value={stats.medium} label="MEDIUM" color="text-yellow-500" />
          <StatCard value={stats.low} label="LOW" color="text-green-500" />
        </div>

        {/* ═══ IMPACT NOTICE ═══ */}
        {stats.excluded > 0 && !showExcluded && (
          <div className="bg-yellow-500/10 border border-yellow-500/30 p-3 flex items-start gap-3">
            <Info className="w-4 h-4 text-yellow-500 mt-0.5 shrink-0" />
            <div className="text-xs">
              <span className="font-medium text-yellow-400">{stats.excluded} asset{stats.excluded > 1 ? 's' : ''} excluded</span>
              <span className="text-muted-foreground"> — these will not be included in campaign generation, threat matching, or risk scoring. </span>
              <button onClick={() => setShowExcluded(true)} className="text-yellow-400 hover:text-yellow-300 underline">View excluded</button>
            </div>
          </div>
        )}

        {/* ═══ FILTERS & SEARCH ═══ */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by hostname, URL, technology, or tag..."
              className="w-full pl-10 pr-4 py-2.5 bg-background border border-border text-sm font-mono focus:outline-none focus:border-primary"
            />
          </div>
          <select value={riskFilter} onChange={(e) => setRiskFilter(e.target.value)} className="px-3 py-2.5 bg-background border border-border text-sm focus:outline-none focus:border-primary">
            <option value="all">All Risk Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className="px-3 py-2.5 bg-background border border-border text-sm focus:outline-none focus:border-primary">
            <option value="all">All Asset Types</option>
            {assetTypes.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
          </select>
          <select value={confidenceFilter} onChange={(e) => setConfidenceFilter(e.target.value)} className="px-3 py-2.5 bg-background border border-border text-sm focus:outline-none focus:border-primary">
            <option value="all">All Confidence</option>
            <option value="high">High (80+)</option>
            <option value="medium">Medium (50-79)</option>
            <option value="low">Low (&lt;50)</option>
          </select>
        </div>

        {/* ═══ BULK ACTIONS ═══ */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <button onClick={selectAll} className="text-[10px] font-display tracking-wider text-primary hover:text-primary/80">SELECT ALL ({filteredAssets.length})</button>
            <span className="text-muted-foreground">·</span>
            <button onClick={selectNone} className="text-[10px] font-display tracking-wider text-muted-foreground hover:text-foreground">DESELECT</button>
            {selectedIds.size > 0 && (
              <>
                <span className="text-muted-foreground">·</span>
                <span className="text-[10px] font-display tracking-wider text-primary">{selectedIds.size} SELECTED</span>
              </>
            )}
          </div>
          {selectedIds.size > 0 && (
            <div className="flex items-center gap-2">
              {!showExcluded ? (
                <Button
                  variant="outline"
                  size="sm"
                  className="font-display tracking-wider text-xs text-red-400 border-red-500/30 hover:bg-red-500/10"
                  onClick={() => setBulkExcludeOpen(true)}
                >
                  <Ban className="w-3.5 h-3.5 mr-1" />
                  EXCLUDE {selectedIds.size}
                </Button>
              ) : (
                <Button
                  variant="outline"
                  size="sm"
                  className="font-display tracking-wider text-xs text-green-400 border-green-500/30 hover:bg-green-500/10"
                  onClick={() => bulkInclude.mutate({ assetIds: Array.from(selectedIds) })}
                >
                  <RotateCcw className="w-3.5 h-3.5 mr-1" />
                  RESTORE {selectedIds.size}
                </Button>
              )}
            </div>
          )}
        </div>

        {/* ═══ BULK EXCLUDE DIALOG ═══ */}
        {bulkExcludeOpen && (
          <div className="bg-red-500/5 border-2 border-red-500/30 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-display text-sm tracking-wider text-red-400">EXCLUDE {selectedIds.size} ASSETS</h3>
              <button onClick={() => setBulkExcludeOpen(false)}><X className="w-4 h-4 text-muted-foreground" /></button>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {EXCLUSION_REASONS.map(r => (
                <button
                  key={r.value}
                  onClick={() => setBulkReason(r.value)}
                  className={`text-left p-2 border text-xs transition-colors ${bulkReason === r.value ? 'border-red-500/50 bg-red-500/10 text-red-400' : 'border-border hover:border-red-500/30'}`}
                >
                  <div className="font-medium">{r.label}</div>
                  <div className="text-[10px] text-muted-foreground mt-0.5">{r.desc}</div>
                </button>
              ))}
            </div>
            {bulkReason === 'custom' && (
              <input
                type="text"
                value={bulkCustomReason}
                onChange={(e) => setBulkCustomReason(e.target.value)}
                placeholder="Enter custom reason..."
                className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-red-500/50"
              />
            )}
            <div className="flex justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={() => setBulkExcludeOpen(false)}>Cancel</Button>
              <Button
                size="sm"
                className="bg-red-600 hover:bg-red-700 font-display tracking-wider text-xs"
                onClick={handleBulkExclude}
                disabled={bulkExclude.isPending}
              >
                {bulkExclude.isPending ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Ban className="w-3 h-3 mr-1" />}
                CONFIRM EXCLUDE
              </Button>
            </div>
          </div>
        )}

        {/* ═══ ASSET LIST ═══ */}
        <div className="space-y-2">
          {filteredAssets.length === 0 ? (
            <div className="bg-card border border-border p-12 text-center">
              <EyeOff className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
              <p className="text-muted-foreground text-sm">
                {showExcluded ? 'No excluded assets' : 'No assets match your filters'}
              </p>
            </div>
          ) : (
            filteredAssets.map((asset: any) => (
              <AssetRow
                key={asset.id}
                asset={asset}
                isSelected={selectedIds.has(asset.id)}
                isExpanded={expandedAssetId === asset.id}
                isExcludedView={showExcluded}
                onToggleSelect={() => toggleSelect(asset.id)}
                onToggleExpand={() => setExpandedAssetId(expandedAssetId === asset.id ? null : asset.id)}
                onExclude={() => {
                  setExcludeDialogAssetId(asset.id);
                  setExcludeReason('wrong_company');
                  setExcludeCustomReason('');
                }}
                onInclude={() => includeAsset.mutate({ assetId: asset.id })}
              />
            ))
          )}
        </div>

        {/* ═══ SINGLE EXCLUDE DIALOG ═══ */}
        {excludeDialogAssetId !== null && (
          <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={() => setExcludeDialogAssetId(null)}>
            <div className="bg-card border-2 border-red-500/30 p-5 max-w-md w-full space-y-4" onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center justify-between">
                <h3 className="font-display text-sm tracking-wider text-red-400">EXCLUDE ASSET</h3>
                <button onClick={() => setExcludeDialogAssetId(null)}><X className="w-4 h-4 text-muted-foreground" /></button>
              </div>
              <p className="text-xs text-muted-foreground">This asset will be removed from the engagement scope. It will not be included in campaign generation, threat matching, or risk scoring.</p>
              <div className="space-y-2">
                {EXCLUSION_REASONS.map(r => (
                  <button
                    key={r.value}
                    onClick={() => setExcludeReason(r.value)}
                    className={`w-full text-left p-2 border text-xs transition-colors ${excludeReason === r.value ? 'border-red-500/50 bg-red-500/10 text-red-400' : 'border-border hover:border-red-500/30'}`}
                  >
                    <div className="font-medium">{r.label}</div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">{r.desc}</div>
                  </button>
                ))}
              </div>
              {excludeReason === 'custom' && (
                <input
                  type="text"
                  value={excludeCustomReason}
                  onChange={(e) => setExcludeCustomReason(e.target.value)}
                  placeholder="Enter custom reason..."
                  className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-red-500/50"
                  autoFocus
                />
              )}
              <div className="flex justify-end gap-2">
                <Button variant="ghost" size="sm" onClick={() => setExcludeDialogAssetId(null)}>Cancel</Button>
                <Button
                  size="sm"
                  className="bg-red-600 hover:bg-red-700 font-display tracking-wider text-xs"
                  onClick={() => handleExclude(excludeDialogAssetId)}
                  disabled={excludeAsset.isPending}
                >
                  {excludeAsset.isPending ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Ban className="w-3 h-3 mr-1" />}
                  EXCLUDE
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* ═══ CONFIRM & PROCEED ═══ */}
        <div className="bg-card border-2 border-primary/40 p-5 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            <h3 className="font-display text-sm tracking-wider">READY TO PROCEED?</h3>
            <p className="text-xs text-muted-foreground mt-1">
              {stats.included} assets will be used for threat matching and campaign generation.
              {stats.excluded > 0 && ` ${stats.excluded} excluded assets will be ignored.`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="font-display tracking-wider text-xs"
              onClick={() => navigate(`/domain-intel/${scanId}`)}
            >
              BACK TO RESULTS
            </Button>
            <Button
              size="sm"
              className="font-display tracking-wider text-xs bg-primary hover:bg-primary/90"
              onClick={() => {
                toast.success('Curation confirmed! Proceeding with campaign generation...');
                navigate(`/domain-intel/${scanId}`);
              }}
            >
              <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
              CONFIRM & PROCEED ({stats.included} assets)
            </Button>
          </div>
        </div>
      </div>
    </AppShell>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/* Helper Components                                              */
/* ═══════════════════════════════════════════════════════════════ */

function StatCard({ value, label, color, active, onClick }: { value: number; label: string; color: string; active?: boolean; onClick?: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`bg-card border p-2.5 text-center transition-colors ${active ? 'border-primary/50 bg-primary/5' : 'border-border'} ${onClick ? 'cursor-pointer hover:border-primary/30' : 'cursor-default'}`}
    >
      <div className={`font-display text-xl ${color}`}>{value}</div>
      <div className="text-[9px] tracking-widest text-muted-foreground">{label}</div>
    </button>
  );
}

function AssetRow({ asset, isSelected, isExpanded, isExcludedView, onToggleSelect, onToggleExpand, onExclude, onInclude }: {
  asset: any; isSelected: boolean; isExpanded: boolean; isExcludedView: boolean;
  onToggleSelect: () => void; onToggleExpand: () => void; onExclude: () => void; onInclude: () => void;
}) {
  const riskBand = asset.riskBand || 'low';
  const riskClass = RISK_COLORS[riskBand] || RISK_COLORS.low;
  const confidence = asset.confidence || 0;
  const technologies = (asset.technologies as string[]) || [];
  const tags = (asset.tags as string[]) || [];
  const findings = (asset.postureFindings as any[]) || [];
  const typeIcon = ASSET_TYPE_ICONS[asset.assetType] || <Globe className="w-4 h-4" />;

  return (
    <div className={`bg-card border transition-colors ${isExcludedView ? 'border-red-500/20 opacity-70' : isSelected ? 'border-primary/50 bg-primary/5' : 'border-border hover:border-primary/20'}`}>
      {/* Main Row */}
      <div className="flex items-center gap-3 p-3">
        {/* Checkbox */}
        <button onClick={onToggleSelect} className={`w-5 h-5 border flex items-center justify-center shrink-0 transition-colors ${isSelected ? 'bg-primary border-primary' : 'border-border hover:border-primary/50'}`}>
          {isSelected && <Check className="w-3 h-3 text-primary-foreground" />}
        </button>

        {/* Type Icon */}
        <div className={`shrink-0 ${riskClass.split(' ')[0]}`}>{typeIcon}</div>

        {/* Main Info */}
        <button onClick={onToggleExpand} className="flex-1 text-left min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm truncate">{asset.hostname}</span>
            {asset.assetType && (
              <span className="text-[9px] font-display tracking-wider px-1.5 py-0.5 bg-secondary text-muted-foreground shrink-0">{asset.assetType.toUpperCase()}</span>
            )}
          </div>
          {asset.url && <div className="text-[10px] text-muted-foreground truncate mt-0.5">{asset.url}</div>}
        </button>

        {/* Confidence */}
        <div className="hidden sm:flex flex-col items-center shrink-0 w-16">
          <div className="text-[9px] tracking-widest text-muted-foreground">CONF</div>
          <div className={`font-display text-sm ${confidence >= 80 ? 'text-green-500' : confidence >= 50 ? 'text-yellow-500' : 'text-red-500'}`}>{confidence}%</div>
        </div>

        {/* Risk Band */}
        <div className={`shrink-0 px-2 py-0.5 text-[9px] font-display tracking-wider border ${riskClass}`}>
          {riskBand.toUpperCase()}
        </div>

        {/* Hybrid Risk Score */}
        {asset.hybridRiskScore != null && (
          <div className="hidden md:block shrink-0 w-12 text-center">
            <div className="text-[9px] tracking-widest text-muted-foreground">RISK</div>
            <div className={`font-display text-sm ${asset.hybridRiskScore >= 80 ? 'text-red-500' : asset.hybridRiskScore >= 60 ? 'text-orange-500' : asset.hybridRiskScore >= 40 ? 'text-yellow-500' : 'text-green-500'}`}>
              {asset.hybridRiskScore}
            </div>
          </div>
        )}

        {/* Impact & Likelihood (new) + Criticality & Vuln Risk */}
        <div className="hidden lg:flex shrink-0 gap-2">
          <div className="w-12 text-center" title="Impact: How bad if this asset were compromised">
            <div className="text-[9px] tracking-widest text-sky-400/70">IMP</div>
            <div className={`font-display text-sm ${(asset.impactScore || 0) >= 70 ? 'text-sky-400' : (asset.impactScore || 0) >= 40 ? 'text-sky-300' : 'text-slate-400'}`}>
              {asset.impactScore || 0}
            </div>
          </div>
          <div className="w-12 text-center" title="Likelihood: How likely this asset is to be exploited (from CVSS + exposure)">
            <div className="text-[9px] tracking-widest text-amber-400/70">LKH</div>
            <div className={`font-display text-sm ${(asset.likelihoodScore || 0) >= 70 ? 'text-amber-400' : (asset.likelihoodScore || 0) >= 40 ? 'text-amber-300' : 'text-slate-400'}`}>
              {asset.likelihoodScore || 0}
            </div>
          </div>
          <div className="w-12 text-center">
            <div className="text-[9px] tracking-widest text-purple-400/70">CRIT</div>
            <div className={`font-display text-sm ${(asset.assetCriticalityScore || 0) >= 70 ? 'text-purple-400' : 'text-slate-400'}`}>
              {asset.assetCriticalityScore || 0}
            </div>
          </div>
          <div className="w-12 text-center">
            <div className="text-[9px] tracking-widest text-muted-foreground">VULN</div>
            <div className={`font-display text-sm ${(asset.vulnRiskScore || 0) >= 70 ? 'text-red-400' : (asset.vulnRiskScore || 0) >= 40 ? 'text-yellow-400' : 'text-emerald-400'}`}>
              {asset.vulnRiskScore || 0}
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1 shrink-0">
          {isExcludedView ? (
            <Button variant="ghost" size="sm" className="text-green-400 hover:text-green-300 hover:bg-green-500/10 h-8 w-8 p-0" onClick={onInclude} title="Restore this asset">
              <RotateCcw className="w-4 h-4" />
            </Button>
          ) : (
            <Button variant="ghost" size="sm" className="text-red-400 hover:text-red-300 hover:bg-red-500/10 h-8 w-8 p-0" onClick={onExclude} title="Exclude this asset">
              <Ban className="w-4 h-4" />
            </Button>
          )}
          <button onClick={onToggleExpand} className="text-muted-foreground hover:text-foreground p-1">
            <ChevronDown className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
          </button>
        </div>
      </div>

      {/* Exclusion reason banner */}
      {isExcludedView && asset.exclusionReason && (
        <div className="px-3 pb-2 flex items-center gap-2 text-xs text-red-400">
          <Ban className="w-3 h-3 shrink-0" />
          <span>Excluded: {asset.exclusionReason}</span>
          {asset.excludedAt && <span className="text-muted-foreground">({new Date(asset.excludedAt).toLocaleDateString()})</span>}
        </div>
      )}

      {/* Expanded Detail */}
      {isExpanded && (
        <div className="border-t border-border p-4 space-y-3 bg-secondary/20">
          {/* Technologies */}
          {technologies.length > 0 && (
            <div>
              <div className="text-[10px] font-display tracking-wider text-muted-foreground mb-1.5">TECHNOLOGIES</div>
              <div className="flex flex-wrap gap-1">
                {technologies.map((t, i) => (
                  <span key={i} className="px-2 py-0.5 text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* Tags */}
          {tags.length > 0 && (
            <div>
              <div className="text-[10px] font-display tracking-wider text-muted-foreground mb-1.5">TAGS</div>
              <div className="flex flex-wrap gap-1">
                {tags.map((t, i) => (
                  <span key={i} className="px-2 py-0.5 text-[10px] bg-primary/10 text-primary border border-primary/20">{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* BIA Scores */}
          {asset.carverScores && (
            <div>
              <div className="text-[10px] font-display tracking-wider text-muted-foreground mb-1.5">IMPACT DIMENSION SCORES</div>
              <div className="grid grid-cols-3 sm:grid-cols-6 gap-1">
                {Object.entries(asset.carverScores as Record<string, number>).map(([key, val]) => (
                  <div key={key} className="bg-background border border-border p-1.5 text-center">
                    <div className="text-[9px] text-muted-foreground uppercase">{key.slice(0, 4)}</div>
                    <div className="font-display text-sm">{val}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Mission Impact & Tier */}
          <div className="flex gap-4">
            {asset.missionImpactScore != null && (
              <div>
                <div className="text-[10px] font-display tracking-wider text-muted-foreground">MISSION IMPACT</div>
                <div className="font-display text-lg">{asset.missionImpactScore}/10</div>
              </div>
            )}
            {asset.suggestedTier && (
              <div>
                <div className="text-[10px] font-display tracking-wider text-muted-foreground">SUGGESTED TIER</div>
                <div className="font-display text-lg uppercase">{asset.suggestedTier}</div>
              </div>
            )}
          </div>

          {/* Posture Findings */}
          {findings.length > 0 && (
            <div>
              <div className="text-[10px] font-display tracking-wider text-muted-foreground mb-1.5">POSTURE FINDINGS ({findings.length})</div>
              <div className="space-y-1">
                {findings.slice(0, 5).map((f: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <AlertTriangle className={`w-3 h-3 mt-0.5 shrink-0 ${f.severity === 'critical' ? 'text-red-500' : f.severity === 'high' ? 'text-orange-500' : 'text-yellow-500'}`} />
                    <span>{f.title || f.description || JSON.stringify(f)}</span>
                  </div>
                ))}
                {findings.length > 5 && <div className="text-[10px] text-muted-foreground">+{findings.length - 5} more findings</div>}
              </div>
            </div>
          )}

          {/* Test Vectors */}
          {asset.testVectors && (asset.testVectors as any[]).length > 0 && (
            <div>
              <div className="text-[10px] font-display tracking-wider text-muted-foreground mb-1.5">RECOMMENDED TEST VECTORS</div>
              <div className="space-y-1">
                {(asset.testVectors as any[]).slice(0, 3).map((v: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <Zap className="w-3 h-3 mt-0.5 shrink-0 text-primary" />
                    <span>{typeof v === 'string' ? v : v.description || v.name || JSON.stringify(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* DNS Records */}
          {asset.dnsRecords && (
            <div>
              <div className="text-[10px] font-display tracking-wider text-muted-foreground mb-1.5">DNS RECORDS</div>
              <pre className="text-[10px] bg-background border border-border p-2 overflow-x-auto font-mono text-muted-foreground max-h-32">
                {typeof asset.dnsRecords === 'string' ? asset.dnsRecords : JSON.stringify(asset.dnsRecords, null, 2)}
              </pre>
            </div>
          )}

          {/* Confidence Explanation */}
          {asset.confidenceExplanation && (
            <div>
              <div className="text-[10px] font-display tracking-wider text-muted-foreground mb-1.5">CONFIDENCE EXPLANATION</div>
              <div className="text-xs text-muted-foreground">
                {typeof asset.confidenceExplanation === 'string' ? asset.confidenceExplanation : JSON.stringify(asset.confidenceExplanation)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
