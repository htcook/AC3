import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import {
  Target, TrendingUp, ShieldAlert, Pencil, CheckCircle2, AlertTriangle, Undo2
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";

interface EntityProfileTabProps {
  entityProfile: any;
  financialImpact: any;
  scanId?: number;
  domain?: string;
}

export default function EntityProfileTab({ entityProfile, financialImpact, scanId, domain }: EntityProfileTabProps) {
  const ep = entityProfile;
  const fi = financialImpact;
  const [overrideOpen, setOverrideOpen] = useState(false);

  // Fetch existing override
  const { data: existingOverride, refetch: refetchOverride } = trpc.domainIntel.getEntityOverride.useQuery(
    { scanId: scanId! },
    { enabled: !!scanId }
  );

  const setOverrideMut = trpc.domainIntel.setEntityOverride.useMutation({
    onSuccess: () => {
      toast.success("Entity profile override saved. Next PDF export will use corrected data.");
      refetchOverride();
      setOverrideOpen(false);
    },
    onError: (err) => toast.error(`Failed to save override: ${err.message}`),
  });

  const deleteOverrideMut = trpc.domainIntel.deleteEntityOverride.useMutation({
    onSuccess: () => {
      toast.success("Entity override removed. Auto-detected profile will be used.");
      refetchOverride();
    },
    onError: (err) => toast.error(`Failed to remove override: ${err.message}`),
  });

  // Form state for override
  const [form, setForm] = useState({
    orgName: "",
    industry: "",
    subSector: "",
    companySize: "" as string,
    estimatedRevenue: "",
    estimatedEmployees: "",
    headquarters: "",
    foundedYear: "",
    isPublicCompany: false,
    stockTicker: "",
    keyProducts: "",
    overrideReason: "",
  });

  const openOverrideModal = () => {
    // Pre-fill with existing override or current auto-detected values
    const source = existingOverride || ep;
    setForm({
      orgName: source?.orgName || "",
      industry: source?.industry || "",
      subSector: source?.subSector || source?.sub_sector || "",
      companySize: source?.companySize || source?.company_size || "",
      estimatedRevenue: source?.estimatedRevenue || source?.estimated_revenue || "",
      estimatedEmployees: source?.estimatedEmployees || source?.estimated_employees || "",
      headquarters: source?.headquarters || "",
      foundedYear: source?.foundedYear || source?.founded_year || "",
      isPublicCompany: source?.isPublicCompany || source?.is_public_company || false,
      stockTicker: source?.stockTicker || source?.stock_ticker || "",
      keyProducts: Array.isArray(source?.keyProducts || source?.key_products)
        ? (source?.keyProducts || source?.key_products).join(", ")
        : "",
      overrideReason: source?.overrideReason || source?.override_reason || "",
    });
    setOverrideOpen(true);
  };

  const handleSaveOverride = () => {
    if (!scanId || !domain) return;
    setOverrideMut.mutate({
      scanId,
      domain,
      orgName: form.orgName || undefined,
      industry: form.industry || undefined,
      subSector: form.subSector || undefined,
      companySize: (form.companySize || undefined) as any,
      estimatedRevenue: form.estimatedRevenue ? Number(form.estimatedRevenue) : undefined,
      estimatedEmployees: form.estimatedEmployees ? Number(form.estimatedEmployees) : undefined,
      headquarters: form.headquarters || undefined,
      foundedYear: form.foundedYear ? Number(form.foundedYear) : undefined,
      isPublicCompany: form.isPublicCompany || undefined,
      stockTicker: form.stockTicker || undefined,
      keyProducts: form.keyProducts ? form.keyProducts.split(",").map(s => s.trim()).filter(Boolean) : undefined,
      overrideReason: form.overrideReason || undefined,
    });
  };

  const fmtCurrency = (v: number | null | undefined) => {
    if (!v) return 'N/A';
    if (v >= 1_000_000_000) return `$${(v / 1_000_000_000).toFixed(1)}B`;
    if (v >= 1_000_000) return `$${(v / 1_000_000).toFixed(1)}M`;
    if (v >= 1_000) return `$${(v / 1_000).toFixed(0)}K`;
    return `$${v.toLocaleString()}`;
  };

  const impactTierColor = (tier: string) => {
    if (tier === 'catastrophic') return 'text-red-400 bg-red-500/20 border-red-500/40';
    if (tier === 'severe') return 'text-orange-400 bg-orange-500/20 border-orange-500/40';
    if (tier === 'significant') return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/40';
    if (tier === 'moderate') return 'text-blue-400 bg-blue-500/20 border-blue-500/40';
    return 'text-emerald-400 bg-emerald-500/20 border-emerald-500/40';
  };

  // Determine which data to display — override takes precedence
  const displayData = existingOverride ? {
    orgName: existingOverride.orgName || ep.orgName,
    industry: existingOverride.industry || ep.industry,
    subSector: existingOverride.subSector || ep.subSector,
    companySize: existingOverride.companySize || ep.companySize,
    estimatedRevenue: existingOverride.estimatedRevenue || ep.estimatedRevenue,
    estimatedEmployees: existingOverride.estimatedEmployees || ep.estimatedEmployees,
    headquarters: existingOverride.headquarters || ep.headquarters,
    foundedYear: existingOverride.foundedYear || ep.foundedYear,
    isPublicCompany: existingOverride.isPublicCompany || ep.isPublicCompany,
    stockTicker: existingOverride.stockTicker || ep.stockTicker,
    keyProducts: existingOverride.keyProducts || ep.keyProducts,
  } : ep;

  return (
    <div className="space-y-4">
      {/* Override Banner */}
      {existingOverride && (
        <div className="flex items-center gap-3 p-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10">
          <CheckCircle2 className="h-5 w-5 text-emerald-400 flex-shrink-0" />
          <div className="flex-1">
            <p className="text-sm font-medium text-emerald-300">Manual Override Active</p>
            <p className="text-xs text-muted-foreground">
              Entity profile has been manually corrected{existingOverride.overrideReason ? `: ${existingOverride.overrideReason}` : ''}. PDF exports will use this data.
            </p>
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="text-xs text-muted-foreground hover:text-red-400"
            onClick={() => {
              if (confirm("Remove entity override? The auto-detected profile will be used again.")) {
                deleteOverrideMut.mutate({ scanId: scanId! });
              }
            }}
          >
            <Undo2 className="h-3 w-3 mr-1" /> Revert
          </Button>
        </div>
      )}

      {/* Low confidence warning */}
      {!existingOverride && ep.confidence && ep.confidence < 50 && (
        <div className="flex items-center gap-3 p-3 rounded-lg border border-amber-500/30 bg-amber-500/10">
          <AlertTriangle className="h-5 w-5 text-amber-400 flex-shrink-0" />
          <div className="flex-1">
            <p className="text-sm font-medium text-amber-300">Low Confidence Detection ({ep.confidence}%)</p>
            <p className="text-xs text-muted-foreground">
              The auto-detected entity profile may be inaccurate. Consider adding a manual override to ensure correct data in reports.
            </p>
          </div>
          {scanId && (
            <Button variant="outline" size="sm" className="text-xs" onClick={openOverrideModal}>
              <Pencil className="h-3 w-3 mr-1" /> Override
            </Button>
          )}
        </div>
      )}

      {/* Entity Identification Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Target className="h-5 w-5 text-primary" />
                Entity Identification
              </CardTitle>
              <CardDescription>
                Multi-signal resolution identified the actual business behind this domain — filtering out hosting providers and CDNs.
              </CardDescription>
            </div>
            {scanId && (
              <Button variant="outline" size="sm" onClick={openOverrideModal}>
                <Pencil className="h-3 w-3 mr-1" /> {existingOverride ? 'Edit Override' : 'Override'}
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-2xl font-bold">{displayData.orgName || 'Unknown Organization'}</h3>
              <div className="flex items-center gap-2 mt-1">
                {displayData.industry && <Badge variant="secondary">{displayData.industry}</Badge>}
                {displayData.subSector && <Badge variant="outline">{displayData.subSector}</Badge>}
                {displayData.isPublicCompany && <Badge variant="outline" className="text-emerald-400 border-emerald-500/40">Public ({displayData.stockTicker})</Badge>}
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm text-muted-foreground">Confidence</div>
              <div className="text-2xl font-bold">{ep.confidence || 0}%</div>
              <div className="text-xs text-muted-foreground">{ep.identificationMethod}</div>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-3 border-t">
            {displayData.headquarters && <div><span className="text-xs text-muted-foreground block">Headquarters</span><span className="text-sm font-medium">{displayData.headquarters}</span></div>}
            {displayData.foundedYear && <div><span className="text-xs text-muted-foreground block">Founded</span><span className="text-sm font-medium">{displayData.foundedYear}</span></div>}
            {displayData.estimatedEmployees && <div><span className="text-xs text-muted-foreground block">Employees</span><span className="text-sm font-medium">{Number(displayData.estimatedEmployees).toLocaleString()}</span></div>}
            {displayData.companySize && <div><span className="text-xs text-muted-foreground block">Company Size</span><span className="text-sm font-medium capitalize">{displayData.companySize}</span></div>}
          </div>

          {/* Evidence Sources */}
          {ep.evidence && ep.evidence.length > 0 && (
            <div className="pt-3 border-t">
              <h4 className="text-sm font-semibold mb-2">Identification Evidence</h4>
              <div className="flex flex-wrap gap-2">
                {ep.evidence.map((e: any, i: number) => (
                  <Badge key={i} variant="outline" className="text-xs">
                    {e.source}: {e.value} ({e.confidence}%)
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* WHOIS / SSL Org */}
          {(ep.whoisOrg || ep.sslCertOrg) && (
            <div className="pt-3 border-t grid grid-cols-2 gap-4">
              {ep.whoisOrg && <div><span className="text-xs text-muted-foreground block">WHOIS Organization</span><span className="text-sm">{ep.whoisOrg} {ep.whoisIsHostingProvider && <Badge variant="outline" className="text-xs text-amber-400 ml-1">Hosting Provider</Badge>}</span></div>}
              {ep.sslCertOrg && <div><span className="text-xs text-muted-foreground block">SSL Certificate Org</span><span className="text-sm">{ep.sslCertOrg}</span></div>}
            </div>
          )}

          {/* Key Products & Social */}
          {displayData.keyProducts && displayData.keyProducts.length > 0 && (
            <div className="pt-3 border-t">
              <h4 className="text-sm font-semibold mb-2">Key Products & Services</h4>
              <div className="flex flex-wrap gap-2">
                {displayData.keyProducts.map((p: string, i: number) => <Badge key={i} variant="secondary" className="text-xs">{p}</Badge>)}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Financial Profile Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-emerald-400" />
            Financial Profile
          </CardTitle>
          <CardDescription>
            Revenue and valuation data used to calibrate BIA financial loss impact ratings.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-3 bg-muted/30 rounded-lg">
              <div className="text-xs text-muted-foreground mb-1">Est. Revenue</div>
              <div className="text-xl font-bold">{fmtCurrency(displayData.estimatedRevenue || ep.estimatedRevenue)}</div>
              {ep.revenueConfidence && <div className="text-xs text-muted-foreground">{ep.revenueConfidence}% confidence</div>}
              {ep.revenueSource && <div className="text-xs text-muted-foreground/60">{ep.revenueSource}</div>}
            </div>
            <div className="text-center p-3 bg-muted/30 rounded-lg">
              <div className="text-xs text-muted-foreground mb-1">Est. Valuation</div>
              <div className="text-xl font-bold">{fmtCurrency(ep.estimatedValuation)}</div>
              {ep.valuationConfidence && <div className="text-xs text-muted-foreground">{ep.valuationConfidence}% confidence</div>}
              {ep.valuationSource && <div className="text-xs text-muted-foreground/60">{ep.valuationSource}</div>}
            </div>
            {fi && (
              <>
                <div className="text-center p-3 bg-muted/30 rounded-lg">
                  <div className="text-xs text-muted-foreground mb-1">Daily Revenue at Risk</div>
                  <div className="text-xl font-bold text-amber-400">{fmtCurrency(fi.estimatedDailyRevenueLoss)}</div>
                </div>
                <div className="text-center p-3 bg-muted/30 rounded-lg">
                  <div className="text-xs text-muted-foreground mb-1">Max Single Incident</div>
                  <div className="text-xl font-bold text-red-400">{fmtCurrency(fi.maxSingleIncidentLoss)}</div>
                </div>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      {/* BIA Impact Assessment Card */}
      {fi && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-red-400" />
              Business Impact Assessment (NIST IR 8286D)
            </CardTitle>
            <CardDescription>
              Financial loss projections calibrated against the identified entity's revenue and valuation data.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-4 p-4 rounded-lg border">
              <div className="flex-1">
                <div className="text-sm text-muted-foreground mb-1">Impact Tier</div>
                <Badge className={`text-lg px-3 py-1 ${impactTierColor(fi.impactTier)}`}>
                  {(fi.impactTier || 'unknown').toUpperCase()}
                </Badge>
              </div>
              <div className="text-right">
                <div className="text-sm text-muted-foreground mb-1">Total Max Exposure</div>
                <div className="text-3xl font-bold text-red-400">{fmtCurrency(fi.totalMaxExposure)}</div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <Card className="bg-muted/20">
                <CardContent className="py-3 text-center">
                  <div className="text-xs text-muted-foreground mb-1">Regulatory Fine Exposure</div>
                  <div className="text-lg font-bold text-orange-400">{fmtCurrency(fi.regulatoryFineExposure)}</div>
                  <div className="text-xs text-muted-foreground/60">GDPR, HIPAA, PCI-DSS, state laws</div>
                </CardContent>
              </Card>
              <Card className="bg-muted/20">
                <CardContent className="py-3 text-center">
                  <div className="text-xs text-muted-foreground mb-1">Reputational Damage</div>
                  <div className="text-lg font-bold text-purple-400">{fmtCurrency(fi.reputationalDamageEstimate)}</div>
                  <div className="text-xs text-muted-foreground/60">Brand value, customer churn</div>
                </CardContent>
              </Card>
              <Card className="bg-muted/20">
                <CardContent className="py-3 text-center">
                  <div className="text-xs text-muted-foreground mb-1">Daily Revenue Loss</div>
                  <div className="text-lg font-bold text-amber-400">{fmtCurrency(fi.estimatedDailyRevenueLoss)}</div>
                  <div className="text-xs text-muted-foreground/60">Per day of operational disruption</div>
                </CardContent>
              </Card>
            </div>

            {fi.rationale && (
              <div className="pt-3 border-t">
                <h4 className="text-sm font-semibold mb-2">Impact Rationale</h4>
                <p className="text-sm text-muted-foreground">{fi.rationale}</p>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Entity Override Dialog */}
      <Dialog open={overrideOpen} onOpenChange={setOverrideOpen}>
        <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Pencil className="h-4 w-4" />
              {existingOverride ? 'Edit Entity Override' : 'Override Entity Profile'}
            </DialogTitle>
            <DialogDescription>
              Correct the auto-detected entity profile. This override will be used in all future PDF exports for this scan.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="orgName">Organization Name</Label>
              <Input id="orgName" value={form.orgName} onChange={e => setForm(f => ({ ...f, orgName: e.target.value }))} placeholder="e.g. Ace of Cloud LLC" />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="industry">Industry</Label>
                <Input id="industry" value={form.industry} onChange={e => setForm(f => ({ ...f, industry: e.target.value }))} placeholder="e.g. Cybersecurity" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="subSector">Sub-Sector</Label>
                <Input id="subSector" value={form.subSector} onChange={e => setForm(f => ({ ...f, subSector: e.target.value }))} placeholder="e.g. Offensive Security" />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="companySize">Company Size</Label>
                <Select value={form.companySize} onValueChange={v => setForm(f => ({ ...f, companySize: v }))}>
                  <SelectTrigger><SelectValue placeholder="Select size" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="startup">Startup (1-10)</SelectItem>
                    <SelectItem value="small">Small (11-50)</SelectItem>
                    <SelectItem value="medium">Medium (51-200)</SelectItem>
                    <SelectItem value="large">Large (201-1000)</SelectItem>
                    <SelectItem value="enterprise">Enterprise (1000+)</SelectItem>
                    <SelectItem value="unknown">Unknown</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="estimatedEmployees">Employees</Label>
                <Input id="estimatedEmployees" type="number" value={form.estimatedEmployees} onChange={e => setForm(f => ({ ...f, estimatedEmployees: e.target.value }))} placeholder="e.g. 25" />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="headquarters">Headquarters</Label>
                <Input id="headquarters" value={form.headquarters} onChange={e => setForm(f => ({ ...f, headquarters: e.target.value }))} placeholder="e.g. Tampa, FL, USA" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="foundedYear">Founded Year</Label>
                <Input id="foundedYear" type="number" value={form.foundedYear} onChange={e => setForm(f => ({ ...f, foundedYear: e.target.value }))} placeholder="e.g. 2022" />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="estimatedRevenue">Est. Revenue ($)</Label>
                <Input id="estimatedRevenue" type="number" value={form.estimatedRevenue} onChange={e => setForm(f => ({ ...f, estimatedRevenue: e.target.value }))} placeholder="e.g. 500000" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="stockTicker">Stock Ticker</Label>
                <Input id="stockTicker" value={form.stockTicker} onChange={e => setForm(f => ({ ...f, stockTicker: e.target.value }))} placeholder="e.g. AAPL (if public)" />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="keyProducts">Key Products (comma-separated)</Label>
              <Input id="keyProducts" value={form.keyProducts} onChange={e => setForm(f => ({ ...f, keyProducts: e.target.value }))} placeholder="e.g. Penetration Testing, Red Team, DI Reports" />
            </div>

            <div className="space-y-2">
              <Label htmlFor="overrideReason">Reason for Override</Label>
              <Textarea id="overrideReason" value={form.overrideReason} onChange={e => setForm(f => ({ ...f, overrideReason: e.target.value }))} placeholder="e.g. Auto-detection matched wrong company (Ahmedabad entity vs actual Tampa company)" rows={2} />
            </div>
          </div>

          <DialogFooter>
            <Button variant="ghost" onClick={() => setOverrideOpen(false)}>Cancel</Button>
            <Button onClick={handleSaveOverride} disabled={setOverrideMut.isPending}>
              {setOverrideMut.isPending ? "Saving..." : "Save Override"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
