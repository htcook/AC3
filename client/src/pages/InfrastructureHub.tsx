import { lazy } from "react";
import type { ComponentType } from "react";
import AppShell from "@/components/AppShell";
import HubTabs from "@/components/HubTabs";
import { Server, Archive, BookMarked, FileText } from "lucide-react";

const LiveInfra = lazy(() => import("./LiveInfra"));
const EvidenceCollection = lazy(() => import("./EvidenceCollection"));
const InfraReference = lazy(() => import("./InfraReference"));
const InfraWiki = lazy(() => import("./InfraWiki"));

const tabs = [
  { id: "live", label: "Live Infrastructure", icon: Server as ComponentType<{ className?: string }>, component: LiveInfra },
  { id: "evidence", label: "Evidence Locker", icon: Archive as ComponentType<{ className?: string }>, component: EvidenceCollection },
  { id: "reference", label: "Infra Reference", icon: BookMarked as ComponentType<{ className?: string }>, component: InfraReference },
  { id: "wiki", label: "Infra Wiki", icon: FileText as ComponentType<{ className?: string }>, component: InfraWiki },
];

export default function InfrastructureHub() {
  return (
    <AppShell activePath="/live-infra">
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Server className="h-6 w-6 text-primary" />
            Infrastructure
          </h1>
          <p className="text-muted-foreground mt-1">
            Live infrastructure monitoring, evidence collection, and reference documentation
          </p>
        </div>
        <HubTabs tabs={tabs} storageKey="infrastructure-hub" />
      </div>
    </AppShell>
  );
}
