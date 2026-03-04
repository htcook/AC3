import AppShell from "@/components/AppShell";
import HubTabs from "@/components/HubTabs";
import { BarChart3, CheckCircle2, Download, Globe2, Link, ShieldCheck } from "lucide-react";
import React, { lazy } from "react";

const KsiDashboard = lazy(() => import("./KsiDashboard"));
const KsiEvidenceChain = lazy(() => import("./KsiEvidenceChain"));
const KsiAutoCollector = lazy(() => import("./KsiAutoCollector"));
const KsiThreatMap = lazy(() => import("./KsiThreatMap"));
const KsiValidation = lazy(() => import("./KsiValidation"));

const tabs = [
  { id: 'dashboard', label: 'Indicators', icon: BarChart3, component: KsiDashboard },
  { id: 'evidence', label: 'Evidence Chain', icon: Link, component: KsiEvidenceChain },
  { id: 'collector', label: 'Auto-Collection', icon: Download, component: KsiAutoCollector },
  { id: 'threats', label: 'Threat Map', icon: Globe2, component: KsiThreatMap },
  { id: 'validation', label: 'Validation', icon: CheckCircle2, component: KsiValidation },
];

export default function KsiHub() {
  return (
    <AppShell activePath="/ksi-dashboard">
      <div className="flex items-center mb-4">
        <ShieldCheck className="w-6 h-6 mr-2" />
        <h1 className="font-display tracking-wider text-xl">Key Security Indicators (KSI)</h1>
      </div>
      <p className="text-muted-foreground mb-6">
        FedRAMP Key Security Indicators (KSIs) — continuous monitoring of evidence chains, threat mapping, and validation across 13 security themes
      </p>
      <HubTabs tabs={tabs} storageKey="ksi-hub" />
    </AppShell>
  );
}
