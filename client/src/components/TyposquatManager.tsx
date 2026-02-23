import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from "@/components/ui/dialog";
import {
  Globe, Search, ShieldAlert, ShieldCheck, Zap, CheckCircle, XCircle,
  Loader2, ExternalLink, Copy, ArrowRight, RefreshCw, AlertTriangle,
  Server, Mail, Settings, ChevronRight, DollarSign, Lock, Unlock,
} from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────

interface TyposquatVariant {
  domain: string;
  technique: string;
  effectiveness: number;
  description: string;
  available?: boolean;
  tld: string;
}

interface TyposquatResult {
  targetDomain: string;
  canSpoof: boolean;
  spoofabilityScore: number;
  spoofabilityReason: string;
  variants: TyposquatVariant[];
  recommendedVariants: TyposquatVariant[];
  generatedAt: string;
}

// ─── Technique Labels ──────────────────────────────────────────────────────

const TECHNIQUE_CONFIG: Record<string, { label: string; color: string; bg: string }> = {
  homoglyph: { label: "HOMOGLYPH", color: "text-red-400", bg: "bg-red-500/15 border-red-500/30" },
  tld_swap: { label: "TLD SWAP", color: "text-orange-400", bg: "bg-orange-500/15 border-orange-500/30" },
  combosquat: { label: "COMBOSQUAT", color: "text-purple-400", bg: "bg-purple-500/15 border-purple-500/30" },
  adjacent_swap: { label: "TYPO", color: "text-yellow-400", bg: "bg-yellow-500/15 border-yellow-500/30" },
  transposition: { label: "TRANSPOSE", color: "text-blue-400", bg: "bg-blue-500/15 border-blue-500/30" },
  missing_dot: { label: "MISSING DOT", color: "text-cyan-400", bg: "bg-cyan-500/15 border-cyan-500/30" },
  omission: { label: "OMISSION", color: "text-emerald-400", bg: "bg-emerald-500/15 border-emerald-500/30" },
  doubling: { label: "DOUBLE", color: "text-pink-400", bg: "bg-pink-500/15 border-pink-500/30" },
  hyphenation: { label: "HYPHEN", color: "text-gray-400", bg: "bg-gray-500/15 border-gray-500/30" },
};

// ─── Effectiveness Bar ─────────────────────────────────────────────────────

function EffectivenessBar({ score }: { score: number }) {
  const color = score >= 8 ? "bg-red-500" : score >= 6 ? "bg-orange-500" : score >= 4 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${score * 10}%` }} />
      </div>
      <span className="text-[10px] font-display tracking-wider text-muted-foreground">{score}/10</span>
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────

export default function TyposquatManager({ engagementId }: { engagementId?: number }) {
  const [targetDomain, setTargetDomain] = useState("");
  const [result, setResult] = useState<TyposquatResult | null>(null);
  const [selectedDomain, setSelectedDomain] = useState<TyposquatVariant | null>(null);
  const [integrationDialogOpen, setIntegrationDialogOpen] = useState(false);
  const [integrationStep, setIntegrationStep] = useState<"confirm" | "purchasing" | "configuring" | "done">("confirm");
  const [fromName, setFromName] = useState("IT Support");
  const [registrar, setRegistrar] = useState("namecheap");
  const [lastTyposquatId, setLastTyposquatId] = useState<number>(0);

  // Mutations
  const generateMutation = trpc.typosquat.generateVariants.useMutation({
    onSuccess: (data: any) => {
      setResult(data);
      // Store the typosquatId if returned from the server for later integration
      if (data.typosquatId) setLastTyposquatId(data.typosquatId);
      toast.success(`Generated ${data.recommendedVariants.length} typosquat variants`);
    },
    onError: (err) => toast.error(`Generation failed: ${sanitizeErrorForToast(err)}`),
  });

  const markPurchasedMutation = trpc.typosquat.markPurchased.useMutation();
  const autoIntegrateMutation = trpc.typosquat.autoIntegrate.useMutation();

  // Handlers
  const handleGenerate = () => {
    if (!targetDomain.trim()) {
      toast.error("Enter a target domain");
      return;
    }
    generateMutation.mutate({
      targetDomain: targetDomain.trim().toLowerCase(),
      engagementId,
      maxVariants: 10,
      checkAvailability: true,
    });
  };

  const handleSelectForPurchase = (variant: TyposquatVariant) => {
    setSelectedDomain(variant);
    setIntegrationStep("confirm");
    setIntegrationDialogOpen(true);
  };

  const handleAutoIntegrate = async () => {
    if (!selectedDomain) return;
    setIntegrationStep("purchasing");

    // Step 1: Mark as purchased (user bought it externally)
    // In a real flow, this would redirect to registrar
    setTimeout(async () => {
      setIntegrationStep("configuring");

      try {
        const res = await autoIntegrateMutation.mutateAsync({
          domain: selectedDomain.domain,
          typosquatId: lastTyposquatId, // Use the ID from the generation result
          engagementId,
          fromName,
          mailServerIp: "137.184.7.224",
        });

        if (res.success) {
          setIntegrationStep("done");
          toast.success(`${selectedDomain.domain} fully integrated with the phishing platform!`);
        } else {
          toast.error("Some integration steps failed. Check the details.");
          setIntegrationStep("done");
        }
      } catch (err: any) {
        toast.error(`Integration failed: ${sanitizeErrorForToast(err)}`);
        setIntegrationStep("confirm");
      }
    }, 1500);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  // ─── Registrar purchase links ──────────────────────────────────────────

  const getRegistrarLink = (domain: string) => {
    const links: Record<string, string> = {
      namecheap: `https://www.namecheap.com/domains/registration/results/?domain=${domain}`,
      godaddy: `https://www.godaddy.com/domainsearch/find?domainToCheck=${domain}`,
      porkbun: `https://porkbun.com/checkout/search?q=${domain}`,
      cloudflare: `https://dash.cloudflare.com/?to=/:account/domains/register/${domain}`,
    };
    return links[registrar] || links.namecheap;
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <Card className="border-emerald-500/30">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="font-display tracking-wider text-lg flex items-center gap-2">
                <Globe className="w-5 h-5 text-emerald-400" />
                TYPOSQUAT DOMAIN ACQUISITION
              </CardTitle>
              <CardDescription className="mt-1">
                Generate, purchase, and auto-integrate typosquat domains into phishing campaigns when target email security prevents direct spoofing.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-end gap-3">
            <div className="flex-1">
              <Label className="text-xs font-display tracking-wider text-muted-foreground">TARGET DOMAIN</Label>
              <Input
                placeholder="example.com"
                value={targetDomain}
                onChange={(e) => setTargetDomain(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleGenerate()}
                className="font-mono mt-1"
              />
            </div>
            <Button
              onClick={handleGenerate}
              disabled={generateMutation.isPending}
              className="font-display tracking-wider bg-emerald-500 hover:bg-emerald-600 text-black"
            >
              {generateMutation.isPending ? (
                <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> ANALYZING...</>
              ) : (
                <><Search className="w-4 h-4 mr-2" /> GENERATE VARIANTS</>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Spoofability Assessment */}
      {result && (
        <Card className={`border ${result.canSpoof ? "border-yellow-500/30" : "border-red-500/30"}`}>
          <CardContent className="pt-4">
            <div className="flex items-start gap-4">
              <div className={`w-12 h-12 flex items-center justify-center shrink-0 ${result.canSpoof ? "bg-yellow-500/20" : "bg-red-500/20"}`}>
                {result.canSpoof ? (
                  <Unlock className="w-6 h-6 text-yellow-400" />
                ) : (
                  <Lock className="w-6 h-6 text-red-400" />
                )}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-1">
                  <span className="font-display tracking-wider text-sm">EMAIL SECURITY ASSESSMENT</span>
                  <Badge variant="outline" className={result.canSpoof ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" : "bg-red-500/15 text-red-400 border-red-500/30"}>
                    {result.spoofabilityScore}/100 SPOOF SCORE
                  </Badge>
                </div>
                <p className="text-sm text-muted-foreground">{result.spoofabilityReason}</p>
                {!result.canSpoof && (
                  <div className="mt-2 flex items-center gap-2 text-xs text-emerald-400">
                    <ArrowRight className="w-3 h-3" />
                    <span className="font-display tracking-wider">TYPOSQUAT DOMAINS RECOMMENDED — Select from the variants below</span>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recommended Variants */}
      {result && result.recommendedVariants.length > 0 && (
        <Card className="border-emerald-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="font-display tracking-wider text-sm flex items-center gap-2">
              <Zap className="w-4 h-4 text-emerald-400" />
              TOP {result.recommendedVariants.length} RECOMMENDED DOMAINS
            </CardTitle>
            <CardDescription className="text-xs">
              Ranked by phishing effectiveness. Available domains can be purchased and auto-integrated with the phishing platform.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-1.5">
              {result.recommendedVariants.map((variant, idx) => {
                const tech = TECHNIQUE_CONFIG[variant.technique] || TECHNIQUE_CONFIG.omission;
                return (
                  <div
                    key={variant.domain}
                    className="flex items-center gap-3 px-3 py-2.5 bg-card border border-border hover:border-emerald-500/40 transition-colors group"
                  >
                    {/* Rank */}
                    <div className="w-6 h-6 bg-emerald-500/20 flex items-center justify-center text-emerald-400 font-display text-xs shrink-0">
                      {idx + 1}
                    </div>

                    {/* Domain name */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm text-foreground">{variant.domain}</span>
                        <button onClick={() => copyToClipboard(variant.domain)} className="opacity-0 group-hover:opacity-100 transition-opacity">
                          <Copy className="w-3 h-3 text-muted-foreground hover:text-foreground" />
                        </button>
                      </div>
                      <p className="text-[10px] text-muted-foreground mt-0.5 truncate">{variant.description}</p>
                    </div>

                    {/* Technique badge */}
                    <Badge variant="outline" className={`${tech.bg} ${tech.color} text-[9px] font-display tracking-wider shrink-0 border`}>
                      {tech.label}
                    </Badge>

                    {/* Effectiveness */}
                    <div className="shrink-0">
                      <EffectivenessBar score={variant.effectiveness} />
                    </div>

                    {/* Availability */}
                    <div className="shrink-0 w-20 text-center">
                      {variant.available === true ? (
                        <Badge variant="outline" className="bg-green-500/15 text-green-400 border-green-500/30 text-[9px] font-display tracking-wider">
                          <CheckCircle className="w-2.5 h-2.5 mr-1" /> AVAIL
                        </Badge>
                      ) : variant.available === false ? (
                        <Badge variant="outline" className="bg-red-500/15 text-red-400 border-red-500/30 text-[9px] font-display tracking-wider">
                          <XCircle className="w-2.5 h-2.5 mr-1" /> TAKEN
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-muted text-muted-foreground text-[9px] font-display tracking-wider">
                          UNKNOWN
                        </Badge>
                      )}
                    </div>

                    {/* Action button */}
                    <Button
                      size="sm"
                      variant="outline"
                      className="font-display tracking-wider text-[10px] h-7 px-2 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10 shrink-0"
                      onClick={() => handleSelectForPurchase(variant)}
                      disabled={variant.available === false}
                    >
                      <DollarSign className="w-3 h-3 mr-1" /> BUY & INTEGRATE
                    </Button>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Integration Workflow Dialog */}
      <Dialog open={integrationDialogOpen} onOpenChange={setIntegrationDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="font-display tracking-wider flex items-center gap-2">
              <Globe className="w-5 h-5 text-emerald-400" />
              DOMAIN INTEGRATION WORKFLOW
            </DialogTitle>
            <DialogDescription>
              Purchase and auto-configure <span className="font-mono text-foreground">{selectedDomain?.domain}</span> for phishing campaigns.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            {/* Workflow Steps */}
            <div className="space-y-3">
              {/* Step 1: Purchase */}
              <div className={`flex items-start gap-3 p-3 border ${integrationStep === "confirm" ? "border-emerald-500/40 bg-emerald-500/5" : integrationStep === "purchasing" ? "border-yellow-500/40 bg-yellow-500/5" : "border-green-500/40 bg-green-500/5"}`}>
                <div className={`w-8 h-8 flex items-center justify-center shrink-0 ${integrationStep === "purchasing" ? "bg-yellow-500/20" : integrationStep !== "confirm" ? "bg-green-500/20" : "bg-emerald-500/20"}`}>
                  {integrationStep === "purchasing" ? (
                    <Loader2 className="w-4 h-4 text-yellow-400 animate-spin" />
                  ) : integrationStep !== "confirm" ? (
                    <CheckCircle className="w-4 h-4 text-green-400" />
                  ) : (
                    <DollarSign className="w-4 h-4 text-emerald-400" />
                  )}
                </div>
                <div className="flex-1">
                  <p className="text-sm font-display tracking-wider">1. PURCHASE DOMAIN</p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Buy <span className="font-mono text-foreground">{selectedDomain?.domain}</span> from your preferred registrar.
                  </p>
                  {integrationStep === "confirm" && (
                    <div className="mt-2 flex items-center gap-2">
                      <select
                        value={registrar}
                        onChange={(e) => setRegistrar(e.target.value)}
                        className="text-xs bg-background border border-border px-2 py-1 font-display tracking-wider"
                      >
                        <option value="namecheap">Namecheap</option>
                        <option value="godaddy">GoDaddy</option>
                        <option value="porkbun">Porkbun</option>
                        <option value="cloudflare">Cloudflare</option>
                      </select>
                      <a
                        href={selectedDomain ? getRegistrarLink(selectedDomain.domain) : "#"}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs font-display tracking-wider text-emerald-400 hover:underline flex items-center gap-1"
                      >
                        OPEN REGISTRAR <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  )}
                </div>
              </div>

              {/* Step 2: Configure DNS */}
              <div className={`flex items-start gap-3 p-3 border ${integrationStep === "configuring" ? "border-yellow-500/40 bg-yellow-500/5" : integrationStep === "done" ? "border-green-500/40 bg-green-500/5" : "border-border"}`}>
                <div className={`w-8 h-8 flex items-center justify-center shrink-0 ${integrationStep === "configuring" ? "bg-yellow-500/20" : integrationStep === "done" ? "bg-green-500/20" : "bg-muted"}`}>
                  {integrationStep === "configuring" ? (
                    <Loader2 className="w-4 h-4 text-yellow-400 animate-spin" />
                  ) : integrationStep === "done" ? (
                    <CheckCircle className="w-4 h-4 text-green-400" />
                  ) : (
                    <Server className="w-4 h-4 text-muted-foreground" />
                  )}
                </div>
                <div>
                  <p className="text-sm font-display tracking-wider">2. CONFIGURE DNS (cloud provider)</p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Auto-create MX, SPF, and DMARC records via cloud DNS API.
                  </p>
                </div>
              </div>

              {/* Step 3: GoPhish Integration */}
              <div className={`flex items-start gap-3 p-3 border ${integrationStep === "done" ? "border-green-500/40 bg-green-500/5" : "border-border"}`}>
                <div className={`w-8 h-8 flex items-center justify-center shrink-0 ${integrationStep === "done" ? "bg-green-500/20" : "bg-muted"}`}>
                  {integrationStep === "done" ? (
                    <CheckCircle className="w-4 h-4 text-green-400" />
                  ) : (
                    <Mail className="w-4 h-4 text-muted-foreground" />
                  )}
                </div>
                <div>
                  <p className="text-sm font-display tracking-wider">3. CREATE GOPHISH SENDING PROFILE</p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Auto-create SMTP sending profile in the phishing platform with the new domain.
                  </p>
                </div>
              </div>
            </div>

            {/* Configuration */}
            {integrationStep === "confirm" && (
              <div className="space-y-3 pt-2 border-t border-border">
                <div>
                  <Label className="text-xs font-display tracking-wider text-muted-foreground">FROM NAME (for phishing profile)</Label>
                  <Input
                    value={fromName}
                    onChange={(e) => setFromName(e.target.value)}
                    placeholder="IT Support"
                    className="font-mono mt-1"
                  />
                </div>
                <div className="text-xs text-muted-foreground space-y-1">
                  <p className="flex items-center gap-1"><Settings className="w-3 h-3" /> <strong>Mail Server:</strong> 137.184.7.224 (Ace C3 mail server)</p>
                  <p className="flex items-center gap-1"><Mail className="w-3 h-3" /> <strong>From Address:</strong> noreply@{selectedDomain?.domain}</p>
                  <p className="flex items-center gap-1"><Server className="w-3 h-3" /> <strong>Nameservers:</strong> ns1/ns2/ns3.digitalocean.com</p>
                </div>
              </div>
            )}

            {/* Done state */}
            {integrationStep === "done" && autoIntegrateMutation.data && (
              <div className="bg-green-500/10 border border-green-500/30 p-3 space-y-2">
                <p className="text-sm font-display tracking-wider text-green-400 flex items-center gap-2">
                  <CheckCircle className="w-4 h-4" /> INTEGRATION COMPLETE
                </p>
                <div className="text-xs text-muted-foreground space-y-1">
                  {autoIntegrateMutation.data.steps?.map((step: any, i: number) => (
                    <p key={i} className="flex items-center gap-2">
                      {step.status === "success" ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <XCircle className="w-3 h-3 text-red-400" />
                      )}
                      <span className={step.status === "success" ? "text-green-400" : "text-red-400"}>
                        {step.step}
                      </span>
                      <span className="text-muted-foreground">— {step.detail}</span>
                    </p>
                  ))}
                </div>
                {autoIntegrateMutation.data.nameservers && (
                  <div className="mt-2 p-2 bg-muted/50 border border-border">
                    <p className="text-[10px] font-display tracking-wider text-yellow-400 mb-1">
                      <AlertTriangle className="w-3 h-3 inline mr-1" /> UPDATE NAMESERVERS AT REGISTRAR
                    </p>
                    <div className="font-mono text-xs text-foreground space-y-0.5">
                      {autoIntegrateMutation.data.nameservers.map((ns: string) => (
                        <p key={ns} className="flex items-center gap-2">
                          <ChevronRight className="w-3 h-3 text-emerald-400" /> {ns}
                          <button onClick={() => copyToClipboard(ns)} className="text-muted-foreground hover:text-foreground">
                            <Copy className="w-3 h-3" />
                          </button>
                        </p>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          <DialogFooter>
            {integrationStep === "confirm" && (
              <>
                <Button variant="outline" onClick={() => setIntegrationDialogOpen(false)} className="font-display tracking-wider">
                  CANCEL
                </Button>
                <Button
                  onClick={handleAutoIntegrate}
                  className="font-display tracking-wider bg-emerald-500 hover:bg-emerald-600 text-black"
                >
                  <Zap className="w-4 h-4 mr-2" /> PURCHASE & AUTO-INTEGRATE
                </Button>
              </>
            )}
            {(integrationStep === "purchasing" || integrationStep === "configuring") && (
              <Button disabled className="font-display tracking-wider">
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                {integrationStep === "purchasing" ? "REGISTERING PURCHASE..." : "CONFIGURING DNS & GOPHISH..."}
              </Button>
            )}
            {integrationStep === "done" && (
              <Button onClick={() => setIntegrationDialogOpen(false)} className="font-display tracking-wider bg-emerald-500 hover:bg-emerald-600 text-black">
                <CheckCircle className="w-4 h-4 mr-2" /> DONE
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* How It Works */}
      {!result && (
        <Card className="border-border">
          <CardContent className="pt-4">
            <p className="font-display tracking-wider text-sm mb-3 text-muted-foreground">HOW IT WORKS</p>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <div className="flex items-start gap-2 p-3 bg-muted/30 border border-border">
                <div className="w-6 h-6 bg-emerald-500/20 flex items-center justify-center text-emerald-400 font-display text-xs shrink-0">1</div>
                <div>
                  <p className="text-xs font-display tracking-wider">SCAN TARGET</p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">Analyze SPF, DKIM, DMARC to determine if direct spoofing is blocked</p>
                </div>
              </div>
              <div className="flex items-start gap-2 p-3 bg-muted/30 border border-border">
                <div className="w-6 h-6 bg-emerald-500/20 flex items-center justify-center text-emerald-400 font-display text-xs shrink-0">2</div>
                <div>
                  <p className="text-xs font-display tracking-wider">GENERATE VARIANTS</p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">Top 10 most effective typosquat domains ranked by phishing success rate</p>
                </div>
              </div>
              <div className="flex items-start gap-2 p-3 bg-muted/30 border border-border">
                <div className="w-6 h-6 bg-emerald-500/20 flex items-center justify-center text-emerald-400 font-display text-xs shrink-0">3</div>
                <div>
                  <p className="text-xs font-display tracking-wider">PURCHASE & CONFIGURE</p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">Buy domain at registrar, auto-configure DNS via cloud provider</p>
                </div>
              </div>
              <div className="flex items-start gap-2 p-3 bg-muted/30 border border-border">
                <div className="w-6 h-6 bg-emerald-500/20 flex items-center justify-center text-emerald-400 font-display text-xs shrink-0">4</div>
                <div>
                  <p className="text-xs font-display tracking-wider">AUTO-INTEGRATE</p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">phishing sending profile created automatically for the new domain</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
