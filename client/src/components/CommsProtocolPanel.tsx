// @ts-nocheck
/**
 * CommsProtocolPanel — Displays extracted communications protocol from uploaded RoE/Test Plan
 * Shows reporting cadence, escalation chain, testing windows, emergency procedures, and deconfliction
 */

import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Radio, Phone, Mail, Clock, Calendar, AlertTriangle, Shield,
  ChevronDown, ChevronUp, Users, FileText, Loader2
} from "lucide-react";
import { useState } from "react";

interface CommsProtocolPanelProps {
  engagementId: number;
}

export default function CommsProtocolPanel({ engagementId }: CommsProtocolPanelProps) {
  const [expanded, setExpanded] = useState(true);
  const commsQ = trpc.roeUpload.getCommsProtocol.useQuery({ engagementId });
  const scopeQ = trpc.roeUpload.getScopeConstraints.useQuery({ engagementId });

  if (commsQ.isLoading || scopeQ.isLoading) {
    return (
      <Card className="bg-card/50 border-border/30">
        <CardContent className="p-6 flex items-center justify-center gap-2 text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading protocol data...
        </CardContent>
      </Card>
    );
  }

  const comms = commsQ.data;
  const scope = scopeQ.data;

  if (!comms && !scope) return null;

  return (
    <div className="space-y-4">
      {/* Communications Protocol */}
      {comms && (
        <Card className="bg-card/50 border-amber-500/20">
          <CardHeader className="pb-2 cursor-pointer" onClick={() => setExpanded(!expanded)}>
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm flex items-center gap-2">
                <Radio className="h-4 w-4 text-amber-400" /> Communications Protocol
                <Badge variant="outline" className="text-[9px] border-amber-500/30 text-amber-400">FROM UPLOADED DOC</Badge>
              </CardTitle>
              {expanded ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
            </div>
            <CardDescription className="text-xs">Extracted from signed RoE/Test Plan — enforced as operational guardrails</CardDescription>
          </CardHeader>
          {expanded && (
            <CardContent className="space-y-3">
              {/* Reporting */}
              <div className="grid grid-cols-2 gap-3 text-sm">
                {comms.reportingCadence && (
                  <div>
                    <span className="text-[10px] text-muted-foreground uppercase">Reporting Cadence</span>
                    <p className="mt-0.5 font-medium">{comms.reportingCadence}</p>
                  </div>
                )}
                {comms.reportingMethod && (
                  <div>
                    <span className="text-[10px] text-muted-foreground uppercase">Method</span>
                    <p className="mt-0.5">{comms.reportingMethod}</p>
                  </div>
                )}
                {comms.statusCheckInFrequency && (
                  <div>
                    <span className="text-[10px] text-muted-foreground uppercase">Status Check-In</span>
                    <p className="mt-0.5">{comms.statusCheckInFrequency}</p>
                  </div>
                )}
                {comms.statusCheckInMethod && (
                  <div>
                    <span className="text-[10px] text-muted-foreground uppercase">Check-In Method</span>
                    <p className="mt-0.5">{comms.statusCheckInMethod}</p>
                  </div>
                )}
              </div>

              {/* Testing Window */}
              {(comms.testingWindowStart || (comms.testingDays as any)?.length > 0) && (
                <>
                  <Separator />
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5">
                      <Clock className="h-3 w-3 inline mr-1" /> TESTING WINDOW
                    </p>
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      {comms.testingWindowStart && (
                        <div>
                          <span className="text-[10px] text-muted-foreground">Hours</span>
                          <p className="mt-0.5">{comms.testingWindowStart} — {comms.testingWindowEnd || 'EOD'}</p>
                        </div>
                      )}
                      {comms.testTimezone && (
                        <div>
                          <span className="text-[10px] text-muted-foreground">Timezone</span>
                          <p className="mt-0.5">{comms.testTimezone}</p>
                        </div>
                      )}
                    </div>
                    {(comms.testingDays as any)?.length > 0 && (
                      <div className="flex gap-1 mt-2">
                        {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((d, i) => {
                          const dayNames = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
                          const active = (comms.testingDays as string[])?.includes(dayNames[i]);
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
              {(comms.blackoutPeriods as any)?.length > 0 && (
                <>
                  <Separator />
                  <div>
                    <p className="text-xs font-medium text-red-400 mb-1.5">
                      <Calendar className="h-3 w-3 inline mr-1" /> BLACKOUT PERIODS
                    </p>
                    {(comms.blackoutPeriods as string[]).map((b, i) => (
                      <div key={i} className="text-sm px-2 py-1 bg-red-500/5 rounded border border-red-500/10 mb-1">{b}</div>
                    ))}
                  </div>
                </>
              )}

              {/* Escalation Chain */}
              {(comms.escalationChain as any)?.length > 0 && (
                <>
                  <Separator />
                  <div>
                    <p className="text-xs font-medium text-amber-400 mb-1.5">ESCALATION CHAIN</p>
                    <div className="space-y-1">
                      {(comms.escalationChain as string[]).map((step, i) => (
                        <div key={i} className="flex items-center gap-2 text-sm">
                          <span className="text-[10px] text-muted-foreground w-5 text-right">{i + 1}.</span>
                          <span>{step}</span>
                        </div>
                      ))}
                    </div>
                    {comms.escalationTimeframe && (
                      <p className="text-xs text-muted-foreground mt-1">Timeframe: {comms.escalationTimeframe}</p>
                    )}
                  </div>
                </>
              )}

              {/* Critical Finding Notification */}
              {comms.criticalFindingNotifyWithin && (
                <>
                  <Separator />
                  <div className="p-2 bg-red-500/5 rounded border border-red-500/10">
                    <p className="text-xs font-medium text-red-400 mb-1">
                      <AlertTriangle className="h-3 w-3 inline mr-1" /> CRITICAL FINDING NOTIFICATION
                    </p>
                    <p className="text-sm">
                      Notify within <strong>{comms.criticalFindingNotifyWithin}</strong>
                      {comms.criticalFindingNotifyMethod && ` via ${comms.criticalFindingNotifyMethod}`}
                    </p>
                    {(comms.criticalFindingNotifyRecipients as any)?.length > 0 && (
                      <p className="text-xs text-muted-foreground mt-1">
                        Recipients: {(comms.criticalFindingNotifyRecipients as string[]).join(', ')}
                      </p>
                    )}
                  </div>
                </>
              )}

              {/* Emergency Halt */}
              {comms.emergencyHaltProcedure && (
                <div className="p-2 bg-amber-500/5 rounded border border-amber-500/10">
                  <p className="text-xs font-medium text-amber-400 mb-1">EMERGENCY HALT PROCEDURE</p>
                  <p className="text-sm">{comms.emergencyHaltProcedure}</p>
                </div>
              )}

              {/* Deconfliction */}
              {comms.deconflictionProcedure && (
                <div className="p-2 bg-purple-500/5 rounded border border-purple-500/10">
                  <p className="text-xs font-medium text-purple-400 mb-1">DECONFLICTION PROCEDURE</p>
                  <p className="text-sm">{comms.deconflictionProcedure}</p>
                  <div className="flex gap-4 mt-1 text-xs text-muted-foreground">
                    {comms.deconflictionPhone && <span><Phone className="h-3 w-3 inline mr-1" />{comms.deconflictionPhone}</span>}
                    {comms.deconflictionEmail && <span><Mail className="h-3 w-3 inline mr-1" />{comms.deconflictionEmail}</span>}
                  </div>
                  {(comms.deconflictionContacts as any)?.length > 0 && (
                    <div className="mt-1 text-xs text-muted-foreground">
                      Contacts: {(comms.deconflictionContacts as string[]).join(', ')}
                    </div>
                  )}
                </div>
              )}

              {/* Reporting Recipients */}
              {(comms.reportingRecipients as any)?.length > 0 && (
                <>
                  <Separator />
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5">REPORTING RECIPIENTS</p>
                    <div className="flex flex-wrap gap-1">
                      {(comms.reportingRecipients as string[]).map((r, i) => (
                        <Badge key={i} variant="outline" className="text-[9px]">{r}</Badge>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          )}
        </Card>
      )}

      {/* Scope Constraints from Uploaded Doc */}
      {scope && (
        <Card className="bg-card/50 border-green-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4 text-green-400" /> Contracted Scope Constraints
              <Badge variant="outline" className="text-[9px] border-green-500/30 text-green-400">ENFORCED</Badge>
            </CardTitle>
            <CardDescription className="text-xs">Hard scope boundaries from the signed document — all operations gated by these constraints</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {/* Permissions Grid */}
            <div className="grid grid-cols-2 gap-2">
              {[
                { label: 'DoS Testing', val: scope.dosAllowed },
                { label: 'Social Engineering', val: scope.socialEngineeringAllowed },
                { label: 'Physical Testing', val: scope.physicalAllowed },
                { label: 'Wireless Testing', val: scope.wirelessAllowed },
                { label: 'Pivoting', val: scope.pivotingAllowed },
                { label: 'Exfiltration', val: scope.exfiltrationAllowed },
                { label: 'Persistence', val: scope.persistenceAllowed },
                { label: 'File Modification', val: scope.fileModificationAllowed },
                { label: 'Credentialed', val: scope.credentialedTesting },
              ].map(p => (
                <div key={p.label} className="flex items-center gap-2 text-xs px-2 py-1.5 bg-muted/10 rounded">
                  <span className={`h-2 w-2 rounded-full ${p.val ? 'bg-green-400' : 'bg-red-400'}`} />
                  <span className={p.val ? 'text-green-400' : 'text-muted-foreground'}>{p.label}</span>
                  <Badge variant="outline" className={`ml-auto text-[9px] ${p.val ? 'border-green-500/30 text-green-400' : 'border-red-500/30 text-red-400'}`}>
                    {p.val ? 'YES' : 'NO'}
                  </Badge>
                </div>
              ))}
            </div>

            {/* Testing Window */}
            {scope.testingStartDate && (
              <>
                <Separator />
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <span className="text-[10px] text-muted-foreground">Testing Start</span>
                    <p className="mt-0.5">{scope.testingStartDate}</p>
                  </div>
                  {scope.testingEndDate && (
                    <div>
                      <span className="text-[10px] text-muted-foreground">Testing End</span>
                      <p className="mt-0.5">{scope.testingEndDate}</p>
                    </div>
                  )}
                </div>
              </>
            )}

            {/* Allowed/Disallowed Testing Types */}
            {(scope.allowedTestingTypes as any)?.length > 0 && (
              <>
                <Separator />
                <div>
                  <p className="text-xs font-medium text-green-400 mb-1.5">ALLOWED TESTING TYPES</p>
                  <div className="flex flex-wrap gap-1">
                    {(scope.allowedTestingTypes as string[]).map((t, i) => (
                      <Badge key={i} variant="outline" className="text-[9px] border-green-500/30 text-green-400">{t}</Badge>
                    ))}
                  </div>
                </div>
              </>
            )}
            {(scope.disallowedTestingTypes as any)?.length > 0 && (
              <div>
                <p className="text-xs font-medium text-red-400 mb-1.5">DISALLOWED TESTING TYPES</p>
                <div className="flex flex-wrap gap-1">
                  {(scope.disallowedTestingTypes as string[]).map((t, i) => (
                    <Badge key={i} variant="outline" className="text-[9px] border-red-500/30 text-red-400">{t}</Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
