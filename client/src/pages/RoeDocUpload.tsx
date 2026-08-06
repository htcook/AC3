// @ts-nocheck
/**
 * RoeDocUpload.tsx — RoE / Test Plan Document Upload & Auto-Engagement Designer
 * ═══════════════════════════════════════════════════════════════════════════════
 * Upload a signed RoE or Test Plan document (PDF/Word) to auto-create a fully
 * configured engagement with scope enforcement, POCs, and comms protocols.
 */

import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "sonner";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useCallback, useRef } from "react";
import { useLocation } from "wouter";
import {
  Upload, FileText, Shield, Users, Radio, Target, Globe, Network,
  CheckCircle, AlertTriangle, Clock, ArrowRight, Loader2, X,
  ChevronDown, ChevronUp, Eye, Phone, Mail, Building, MapPin,
  Calendar, Lock, Unlock, FileWarning, Zap, Briefcase
} from "lucide-react";

type ParsedData = {
  documentType: string;
  confidence: number;
  warnings: string[];
  engagement: Record<string, any>;
  personnel: Array<Record<string, any>>;
  commsProtocol: Record<string, any>;
  scope: Record<string, any>;
};

export default function RoeDocUpload() {
  const [, navigate] = useLocation();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [uploadedDocId, setUploadedDocId] = useState<number | null>(null);
  const [parsed, setParsed] = useState<ParsedData | null>(null);
  const [showRawText, setShowRawText] = useState(false);

  // Override fields
  const [overrideName, setOverrideName] = useState('');
  const [overrideCustomer, setOverrideCustomer] = useState('');
  const [overrideType, setOverrideType] = useState('');
  const [overrideStart, setOverrideStart] = useState('');
  const [overrideEnd, setOverrideEnd] = useState('');

  const uploadMutation = trpc.roeUpload.uploadAndParse.useMutation();
  const createMutation = trpc.roeUpload.createEngagementFromDoc.useMutation();

  // ─── File Upload Handler ────────────────────────────────────────────────
  const handleFile = useCallback(async (file: File) => {
    if (!file) return;

    const allowedTypes = [
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/msword',
    ];
    if (!allowedTypes.includes(file.type)) {
      toast.error('Unsupported file type. Please upload a PDF or Word (.docx) document.');
      return;
    }
    if (file.size > 50 * 1024 * 1024) {
      toast.error('File too large. Maximum size is 50MB.');
      return;
    }

    setUploading(true);
    setParsed(null);
    setUploadedDocId(null);

    try {
      // Read file as base64
      const buffer = await file.arrayBuffer();
      const base64 = btoa(
        new Uint8Array(buffer).reduce((data, byte) => data + String.fromCharCode(byte), '')
      );

      const result = await uploadMutation.mutateAsync({
        filename: file.name,
        mimeType: file.type,
        fileBase64: base64,
      });

      setUploadedDocId(result.uploadedDocId);
      setParsed(result.parsed as ParsedData);

      // Pre-fill overrides from parsed data
      if (result.parsed?.engagement) {
        const eng = result.parsed.engagement as any;
        setOverrideName(eng.engagementName || '');
        setOverrideCustomer(eng.customerName || '');
        setOverrideType(eng.engagementType || '');
        setOverrideStart(eng.startDate || '');
        setOverrideEnd(eng.endDate || '');
      }

      toast.success(`Document parsed successfully — ${result.parsed?.confidence || 0}% confidence`);
    } catch (err: any) {
      toast.error(sanitizeErrorForToast(err?.message || 'Failed to upload and parse document'));
    } finally {
      setUploading(false);
    }
  }, [uploadMutation]);

  // ─── Create Engagement Handler ──────────────────────────────────────────
  const handleCreate = useCallback(async () => {
    if (!uploadedDocId || !parsed) return;

    setCreating(true);
    try {
      const result = await createMutation.mutateAsync({
        uploadedDocId,
        overrides: {
          engagementName: overrideName || undefined,
          customerName: overrideCustomer || undefined,
          engagementType: (overrideType as any) || undefined,
          startDate: overrideStart || undefined,
          endDate: overrideEnd || undefined,
        },
      });

      toast.success(`Engagement #${result.engagementId} created with ${result.personnelCreated} POCs`);

      if (result.warnings.length > 0) {
        result.warnings.forEach(w => toast.warning(w));
      }

      // Navigate to the new engagement
      setTimeout(() => navigate(`/engagements/${result.engagementId}`), 1000);
    } catch (err: any) {
      toast.error(sanitizeErrorForToast(err?.message || 'Failed to create engagement'));
    } finally {
      setCreating(false);
    }
  }, [uploadedDocId, parsed, overrideName, overrideCustomer, overrideType, overrideStart, overrideEnd, createMutation, navigate]);

  // ─── Drag & Drop ───────────────────────────────────────────────────────
  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') setDragActive(true);
    else if (e.type === 'dragleave') setDragActive(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files?.[0]) handleFile(e.dataTransfer.files[0]);
  }, [handleFile]);

  // ─── Render ─────────────────────────────────────────────────────────────
  return (
    <div className="max-w-6xl mx-auto px-4 py-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-2xl tracking-wider flex items-center gap-3">
            <Upload className="h-6 w-6 text-primary" />
            DOCUMENT UPLOAD — AUTO-ENGAGEMENT DESIGNER
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Upload a signed RoE, Pentest Plan, or Red Team Plan to auto-create a fully configured engagement
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => navigate('/engagements')} className="font-display tracking-wider">
          <ArrowRight className="w-4 h-4 mr-2 rotate-180" /> BACK
        </Button>
      </div>

      {/* Upload Zone */}
      {!parsed && (
        <Card className={`border-2 border-dashed transition-colors ${dragActive ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'}`}>
          <CardContent className="p-12"
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <div className="flex flex-col items-center gap-4 text-center">
              {uploading ? (
                <>
                  <Loader2 className="h-12 w-12 text-primary animate-spin" />
                  <div>
                    <p className="font-display tracking-wider text-lg">PARSING DOCUMENT...</p>
                    <p className="text-muted-foreground text-sm mt-1">
                      Extracting text, identifying POCs, comms protocols, scope constraints, and engagement parameters
                    </p>
                  </div>
                </>
              ) : (
                <>
                  <div className="p-4 rounded-full bg-primary/10">
                    <Upload className="h-10 w-10 text-primary" />
                  </div>
                  <div>
                    <p className="font-display tracking-wider text-lg">DROP YOUR DOCUMENT HERE</p>
                    <p className="text-muted-foreground text-sm mt-1">
                      Supports PDF and Word (.docx) — RoE, Pentest Plans, Red Team Plans, Test Plans
                    </p>
                  </div>
                  <div className="flex gap-3 mt-2">
                    <Button onClick={() => fileInputRef.current?.click()} className="font-display tracking-wider">
                      <FileText className="w-4 h-4 mr-2" /> SELECT FILE
                    </Button>
                  </div>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pdf,.docx,.doc"
                    className="hidden"
                    onChange={(e) => { if (e.target.files?.[0]) handleFile(e.target.files[0]); }}
                  />
                  <div className="flex flex-wrap gap-2 mt-4 justify-center">
                    {['Rules of Engagement', 'Pentest Plan', 'Red Team Plan', 'Test Plan', 'Bug Bounty Scope'].map(t => (
                      <Badge key={t} variant="outline" className="text-xs">{t}</Badge>
                    ))}
                  </div>
                </>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Parsed Results */}
      {parsed && (
        <div className="space-y-6">
          {/* Confidence & Warnings Banner */}
          <Card className={`border-l-4 ${parsed.confidence >= 70 ? 'border-l-green-500 bg-green-500/5' : parsed.confidence >= 40 ? 'border-l-yellow-500 bg-yellow-500/5' : 'border-l-red-500 bg-red-500/5'}`}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {parsed.confidence >= 70 ? <CheckCircle className="h-5 w-5 text-green-400" /> : parsed.confidence >= 40 ? <AlertTriangle className="h-5 w-5 text-yellow-400" /> : <FileWarning className="h-5 w-5 text-red-400" />}
                  <div>
                    <p className="font-display tracking-wider text-sm">
                      {parsed.documentType.replace(/_/g, ' ').toUpperCase()} — {parsed.confidence}% CONFIDENCE
                    </p>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      {parsed.personnel.length} POCs extracted · {parsed.scope?.inScopeDomains?.length || 0} domains · {parsed.scope?.inScopeIpRanges?.length || 0} IP ranges
                    </p>
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button variant="ghost" size="sm" onClick={() => { setParsed(null); setUploadedDocId(null); }}>
                    <X className="w-4 h-4 mr-1" /> RESET
                  </Button>
                </div>
              </div>
              {parsed.warnings.length > 0 && (
                <div className="mt-3 space-y-1">
                  {parsed.warnings.map((w, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs text-yellow-400">
                      <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
                      <span>{w}</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left Column: Engagement Details & Overrides */}
            <div className="space-y-4">
              {/* Engagement Parameters */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Briefcase className="h-4 w-4" /> Engagement Parameters
                  </CardTitle>
                  <CardDescription className="text-xs">Review and override extracted values before creating</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <Label className="text-xs text-muted-foreground">Engagement Name</Label>
                    <Input
                      value={overrideName}
                      onChange={e => setOverrideName(e.target.value)}
                      placeholder={parsed.engagement.engagementName || 'Auto-generated'}
                      className="mt-1"
                    />
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground">Customer / Organization</Label>
                    <Input
                      value={overrideCustomer}
                      onChange={e => setOverrideCustomer(e.target.value)}
                      placeholder={parsed.engagement.customerName || parsed.engagement.organizationName || 'Extracted from document'}
                      className="mt-1"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <Label className="text-xs text-muted-foreground">Type</Label>
                      <select
                        value={overrideType || parsed.engagement.engagementType || ''}
                        onChange={e => setOverrideType(e.target.value)}
                        className="mt-1 w-full bg-background border border-border rounded px-3 py-2 text-sm"
                      >
                        <option value="">Auto-detect</option>
                        <option value="red_team">Red Team</option>
                        <option value="pentest">Pentest</option>
                        <option value="purple_team">Purple Team</option>
                        <option value="phishing">Phishing</option>
                        <option value="tabletop">Tabletop</option>
                      </select>
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">Status</Label>
                      <div className="mt-1 px-3 py-2 bg-muted/20 border border-border rounded text-sm text-muted-foreground">
                        Planning (default)
                      </div>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <Label className="text-xs text-muted-foreground">Start Date</Label>
                      <Input
                        type="date"
                        value={overrideStart}
                        onChange={e => setOverrideStart(e.target.value)}
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">End Date</Label>
                      <Input
                        type="date"
                        value={overrideEnd}
                        onChange={e => setOverrideEnd(e.target.value)}
                        className="mt-1"
                      />
                    </div>
                  </div>

                  {/* Extracted metadata */}
                  {(parsed.engagement.description || parsed.engagement.purpose) && (
                    <div>
                      <Label className="text-xs text-muted-foreground">Description / Purpose</Label>
                      <p className="text-sm mt-1 text-foreground/80 line-clamp-3">{parsed.engagement.description || parsed.engagement.purpose}</p>
                    </div>
                  )}
                  {parsed.engagement.methodology && (
                    <div>
                      <Label className="text-xs text-muted-foreground">Methodology</Label>
                      <p className="text-sm mt-1 text-foreground/80 line-clamp-2">{parsed.engagement.methodology}</p>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Scope */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Target className="h-4 w-4 text-green-400" /> Scope Constraints
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {/* In-Scope */}
                  <div>
                    <p className="text-xs font-medium text-green-400 mb-1.5">IN-SCOPE TARGETS</p>
                    <div className="space-y-1">
                      {(parsed.scope?.inScopeDomains || []).map((d: string, i: number) => (
                        <div key={`d-${i}`} className="flex items-center gap-2 text-sm px-2 py-1 bg-green-500/5 rounded border border-green-500/10">
                          <Globe className="h-3.5 w-3.5 text-green-400" /> {d}
                        </div>
                      ))}
                      {(parsed.scope?.inScopeIpRanges || []).map((ip: string, i: number) => (
                        <div key={`ip-${i}`} className="flex items-center gap-2 text-sm px-2 py-1 bg-green-500/5 rounded border border-green-500/10">
                          <Network className="h-3.5 w-3.5 text-green-400" /> {ip}
                        </div>
                      ))}
                      {(parsed.scope?.inScopeApplications || []).map((a: string, i: number) => (
                        <div key={`app-${i}`} className="flex items-center gap-2 text-sm px-2 py-1 bg-green-500/5 rounded border border-green-500/10">
                          <Shield className="h-3.5 w-3.5 text-green-400" /> {a}
                        </div>
                      ))}
                      {!parsed.scope?.inScopeDomains?.length && !parsed.scope?.inScopeIpRanges?.length && !parsed.scope?.inScopeApplications?.length && (
                        <p className="text-xs text-muted-foreground italic">No in-scope targets extracted</p>
                      )}
                    </div>
                  </div>
                  {/* Out-of-Scope */}
                  {(parsed.scope?.outOfScopeDomains?.length > 0 || parsed.scope?.outOfScopeIpRanges?.length > 0) && (
                    <div>
                      <p className="text-xs font-medium text-red-400 mb-1.5">OUT-OF-SCOPE</p>
                      <div className="space-y-1">
                        {(parsed.scope?.outOfScopeDomains || []).map((d: string, i: number) => (
                          <div key={`od-${i}`} className="flex items-center gap-2 text-sm px-2 py-1 bg-red-500/5 rounded border border-red-500/10">
                            <Globe className="h-3.5 w-3.5 text-red-400" /> {d}
                          </div>
                        ))}
                        {(parsed.scope?.outOfScopeIpRanges || []).map((ip: string, i: number) => (
                          <div key={`oip-${i}`} className="flex items-center gap-2 text-sm px-2 py-1 bg-red-500/5 rounded border border-red-500/10">
                            <Network className="h-3.5 w-3.5 text-red-400" /> {ip}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {/* Permissions Grid */}
                  <Separator />
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-2">TESTING PERMISSIONS</p>
                    <div className="grid grid-cols-2 gap-2">
                      {[
                        { label: 'DoS Testing', val: parsed.scope?.dosAllowed },
                        { label: 'Social Engineering', val: parsed.scope?.socialEngineeringAllowed },
                        { label: 'Physical Testing', val: parsed.scope?.physicalAllowed },
                        { label: 'Wireless Testing', val: parsed.scope?.wirelessAllowed },
                        { label: 'Pivoting', val: parsed.scope?.pivotingAllowed },
                        { label: 'Exfiltration', val: parsed.scope?.exfiltrationAllowed },
                        { label: 'Persistence', val: parsed.scope?.persistenceAllowed },
                        { label: 'File Modification', val: parsed.scope?.fileModificationAllowed },
                        { label: 'Credentialed Testing', val: parsed.scope?.credentialedTesting },
                      ].map(p => (
                        <div key={p.label} className="flex items-center gap-2 text-xs px-2 py-1.5 bg-muted/10 rounded">
                          {p.val ? <Lock className="h-3 w-3 text-green-400" /> : <Unlock className="h-3 w-3 text-red-400" />}
                          <span className={p.val ? 'text-green-400' : 'text-muted-foreground'}>{p.label}</span>
                          <Badge variant="outline" className={`ml-auto text-[9px] ${p.val ? 'border-green-500/30 text-green-400' : 'border-red-500/30 text-red-400'}`}>
                            {p.val ? 'ALLOWED' : 'DENIED'}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Right Column: Personnel & Comms */}
            <div className="space-y-4">
              {/* Personnel / POCs */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Users className="h-4 w-4 text-blue-400" /> Points of Contact ({parsed.personnel.length})
                  </CardTitle>
                  <CardDescription className="text-xs">Extracted from document — will be added to RoE personnel</CardDescription>
                </CardHeader>
                <CardContent>
                  {parsed.personnel.length === 0 ? (
                    <p className="text-xs text-muted-foreground italic text-center py-4">No personnel extracted — add manually after creation</p>
                  ) : (
                    <div className="space-y-2">
                      {parsed.personnel.map((p, i) => (
                        <div key={i} className="p-3 bg-muted/10 rounded border border-border/50">
                          <div className="flex items-start justify-between">
                            <div className="flex items-center gap-2">
                              <div className="p-1.5 rounded bg-blue-500/10">
                                <Users className="h-3.5 w-3.5 text-blue-400" />
                              </div>
                              <div>
                                <p className="text-sm font-medium">{p.name}</p>
                                <p className="text-xs text-muted-foreground">{p.title || p.role?.replace(/_/g, ' ')}</p>
                              </div>
                            </div>
                            <Badge variant="outline" className="text-[9px]">
                              {(p.role || 'unknown').replace(/_/g, ' ').toUpperCase()}
                            </Badge>
                          </div>
                          <div className="mt-2 flex flex-wrap gap-3 text-xs text-muted-foreground">
                            {p.organization && (
                              <span className="flex items-center gap-1"><Building className="h-3 w-3" /> {p.organization}</span>
                            )}
                            {p.email && (
                              <span className="flex items-center gap-1"><Mail className="h-3 w-3" /> {p.email}</span>
                            )}
                            {p.phone && (
                              <span className="flex items-center gap-1"><Phone className="h-3 w-3" /> {p.phone}</span>
                            )}
                            {p.clearanceLevel && (
                              <span className="flex items-center gap-1"><Shield className="h-3 w-3" /> {p.clearanceLevel}</span>
                            )}
                            {p.isPrimary && (
                              <Badge className="text-[9px] bg-primary/20 text-primary border-primary/30">PRIMARY</Badge>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Communications Protocol */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Radio className="h-4 w-4 text-amber-400" /> Communications Protocol
                  </CardTitle>
                  <CardDescription className="text-xs">Reporting cadence, escalation chain, testing windows, and emergency procedures</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {!parsed.commsProtocol || Object.keys(parsed.commsProtocol).length === 0 ? (
                    <p className="text-xs text-muted-foreground italic text-center py-4">No communications protocol extracted</p>
                  ) : (
                    <>
                      {/* Reporting */}
                      <div className="grid grid-cols-2 gap-3">
                        {parsed.commsProtocol.reportingCadence && (
                          <div>
                            <p className="text-[10px] text-muted-foreground uppercase">Reporting Cadence</p>
                            <p className="text-sm mt-0.5">{parsed.commsProtocol.reportingCadence}</p>
                          </div>
                        )}
                        {parsed.commsProtocol.reportingMethod && (
                          <div>
                            <p className="text-[10px] text-muted-foreground uppercase">Method</p>
                            <p className="text-sm mt-0.5">{parsed.commsProtocol.reportingMethod}</p>
                          </div>
                        )}
                        {parsed.commsProtocol.statusCheckInFrequency && (
                          <div>
                            <p className="text-[10px] text-muted-foreground uppercase">Status Check-In</p>
                            <p className="text-sm mt-0.5">{parsed.commsProtocol.statusCheckInFrequency}</p>
                          </div>
                        )}
                        {parsed.commsProtocol.statusCheckInMethod && (
                          <div>
                            <p className="text-[10px] text-muted-foreground uppercase">Check-In Method</p>
                            <p className="text-sm mt-0.5">{parsed.commsProtocol.statusCheckInMethod}</p>
                          </div>
                        )}
                      </div>

                      {/* Testing Window */}
                      {(parsed.commsProtocol.testingWindowStart || parsed.commsProtocol.testingDays?.length > 0) && (
                        <>
                          <Separator />
                          <div>
                            <p className="text-xs font-medium text-muted-foreground mb-1.5">TESTING WINDOW</p>
                            <div className="grid grid-cols-2 gap-3">
                              {parsed.commsProtocol.testingWindowStart && (
                                <div>
                                  <p className="text-[10px] text-muted-foreground">Hours</p>
                                  <p className="text-sm">{parsed.commsProtocol.testingWindowStart} — {parsed.commsProtocol.testingWindowEnd || 'EOD'}</p>
                                </div>
                              )}
                              {parsed.commsProtocol.testTimezone && (
                                <div>
                                  <p className="text-[10px] text-muted-foreground">Timezone</p>
                                  <p className="text-sm">{parsed.commsProtocol.testTimezone}</p>
                                </div>
                              )}
                            </div>
                            {parsed.commsProtocol.testingDays?.length > 0 && (
                              <div className="flex gap-1 mt-2">
                                {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((d, i) => {
                                  const dayNames = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
                                  const active = parsed!.commsProtocol.testingDays?.includes(dayNames[i]);
                                  return (
                                    <Badge key={d} variant={active ? 'default' : 'outline'} className={`text-[9px] ${active ? 'bg-primary/20 text-primary' : 'text-muted-foreground'}`}>
                                      {d}
                                    </Badge>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                        </>
                      )}

                      {/* Blackout Periods */}
                      {parsed.commsProtocol.blackoutPeriods?.length > 0 && (
                        <>
                          <Separator />
                          <div>
                            <p className="text-xs font-medium text-red-400 mb-1.5">BLACKOUT PERIODS</p>
                            {parsed.commsProtocol.blackoutPeriods.map((b: string, i: number) => (
                              <div key={i} className="text-sm px-2 py-1 bg-red-500/5 rounded border border-red-500/10 mb-1">
                                <Calendar className="h-3 w-3 inline mr-1 text-red-400" /> {b}
                              </div>
                            ))}
                          </div>
                        </>
                      )}

                      {/* Escalation Chain */}
                      {parsed.commsProtocol.escalationChain?.length > 0 && (
                        <>
                          <Separator />
                          <div>
                            <p className="text-xs font-medium text-amber-400 mb-1.5">ESCALATION CHAIN</p>
                            <div className="space-y-1">
                              {parsed.commsProtocol.escalationChain.map((step: string, i: number) => (
                                <div key={i} className="flex items-center gap-2 text-sm">
                                  <span className="text-[10px] text-muted-foreground w-5 text-right">{i + 1}.</span>
                                  <span>{step}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </>
                      )}

                      {/* Critical Finding Notification */}
                      {parsed.commsProtocol.criticalFindingNotifyWithin && (
                        <>
                          <Separator />
                          <div className="p-2 bg-red-500/5 rounded border border-red-500/10">
                            <p className="text-xs font-medium text-red-400 mb-1">CRITICAL FINDING NOTIFICATION</p>
                            <p className="text-sm">
                              Notify within <strong>{parsed.commsProtocol.criticalFindingNotifyWithin}</strong>
                              {parsed.commsProtocol.criticalFindingNotifyMethod && ` via ${parsed.commsProtocol.criticalFindingNotifyMethod}`}
                            </p>
                          </div>
                        </>
                      )}

                      {/* Emergency Halt */}
                      {parsed.commsProtocol.emergencyHaltProcedure && (
                        <div className="p-2 bg-amber-500/5 rounded border border-amber-500/10">
                          <p className="text-xs font-medium text-amber-400 mb-1">EMERGENCY HALT PROCEDURE</p>
                          <p className="text-sm line-clamp-3">{parsed.commsProtocol.emergencyHaltProcedure}</p>
                        </div>
                      )}

                      {/* Deconfliction */}
                      {parsed.commsProtocol.deconflictionProcedure && (
                        <div className="p-2 bg-purple-500/5 rounded border border-purple-500/10">
                          <p className="text-xs font-medium text-purple-400 mb-1">DECONFLICTION PROCEDURE</p>
                          <p className="text-sm line-clamp-3">{parsed.commsProtocol.deconflictionProcedure}</p>
                          {parsed.commsProtocol.deconflictionPhone && (
                            <p className="text-xs mt-1 text-muted-foreground"><Phone className="h-3 w-3 inline mr-1" />{parsed.commsProtocol.deconflictionPhone}</p>
                          )}
                          {parsed.commsProtocol.deconflictionEmail && (
                            <p className="text-xs text-muted-foreground"><Mail className="h-3 w-3 inline mr-1" />{parsed.commsProtocol.deconflictionEmail}</p>
                          )}
                        </div>
                      )}
                    </>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Create Engagement Button */}
          <Card className="border-primary/30 bg-primary/5">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-display tracking-wider text-lg">READY TO CREATE ENGAGEMENT</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    This will create an engagement, RoE document, {parsed.personnel.length} POC records,
                    comms protocol, scope constraints, and set the roeScopeGuard for enforcement.
                  </p>
                </div>
                <Button
                  onClick={handleCreate}
                  disabled={creating}
                  size="lg"
                  className="font-display tracking-wider"
                >
                  {creating ? (
                    <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> CREATING...</>
                  ) : (
                    <><Zap className="w-4 h-4 mr-2" /> CREATE ENGAGEMENT</>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
