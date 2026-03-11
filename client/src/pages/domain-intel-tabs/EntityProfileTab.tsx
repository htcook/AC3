// @ts-nocheck
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  ArrowLeft, Shield, Target, AlertTriangle, Brain, Globe, Server,
  ChevronDown, ChevronUp, Crosshair, Zap, FileText, ExternalLink,
  Activity, Lock, Eye, Network, Loader2, BarChart3, Bug, Skull, Database, Cpu,
  TrendingUp, Fingerprint, Radar, Info, Search, Radio, Scan, Flag, Undo2, MessageSquare,
  Download, FlaskConical, Mail, ShieldAlert, ShieldCheck, ShieldX, CheckCircle2, XCircle, RefreshCw,
  Layers, Play, Pause, Settings2, GitBranch, Link2, Users, Hash, Clock, Unplug, Wifi,
  Workflow, Lightbulb, Route, Telescope, ShieldQuestion, ArrowRightLeft, KeyRound,
  Box, ClipboardCheck, PackageSearch, GitCompareArrows
} from "lucide-react";

export default function EntityProfileTab({ entityProfile, financialImpact }: { entityProfile: any; financialImpact: any }) {
  const ep = entityProfile;
  const fi = financialImpact;

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

  return (
    <div className="space-y-4">
      {/* Entity Identification Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="h-5 w-5 text-primary" />
            Entity Identification
          </CardTitle>
          <CardDescription>
            Multi-signal resolution identified the actual business behind this domain — filtering out hosting providers and CDNs.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-2xl font-bold">{ep.orgName || 'Unknown Organization'}</h3>
              <div className="flex items-center gap-2 mt-1">
                {ep.industry && <Badge variant="secondary">{ep.industry}</Badge>}
                {ep.subSector && <Badge variant="outline">{ep.subSector}</Badge>}
                {ep.isPublicCompany && <Badge variant="outline" className="text-emerald-400 border-emerald-500/40">Public ({ep.stockTicker})</Badge>}
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm text-muted-foreground">Confidence</div>
              <div className="text-2xl font-bold">{ep.confidence || 0}%</div>
              <div className="text-xs text-muted-foreground">{ep.identificationMethod}</div>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-3 border-t">
            {ep.headquarters && <div><span className="text-xs text-muted-foreground block">Headquarters</span><span className="text-sm font-medium">{ep.headquarters}</span></div>}
            {ep.foundedYear && <div><span className="text-xs text-muted-foreground block">Founded</span><span className="text-sm font-medium">{ep.foundedYear}</span></div>}
            {ep.estimatedEmployees && <div><span className="text-xs text-muted-foreground block">Employees</span><span className="text-sm font-medium">{ep.estimatedEmployees.toLocaleString()}</span></div>}
            {ep.companySize && <div><span className="text-xs text-muted-foreground block">Company Size</span><span className="text-sm font-medium capitalize">{ep.companySize}</span></div>}
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
          {ep.keyProducts && ep.keyProducts.length > 0 && (
            <div className="pt-3 border-t">
              <h4 className="text-sm font-semibold mb-2">Key Products & Services</h4>
              <div className="flex flex-wrap gap-2">
                {ep.keyProducts.map((p: string, i: number) => <Badge key={i} variant="secondary" className="text-xs">{p}</Badge>)}
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
              <div className="text-xl font-bold">{fmtCurrency(ep.estimatedRevenue)}</div>
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
    </div>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   Vendor Alert Correlation Tab Component
   ═══════════════════════════════════════════════════════════════════════════ */


