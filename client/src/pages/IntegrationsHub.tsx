import { lazy } from "react";
import type { ComponentType } from "react";
import AppShell from "@/components/AppShell";
import HubTabs from "@/components/HubTabs";
import { Webhook, Database, MessageSquare, Workflow, GitBranch, Network } from "lucide-react";

const IntegrationRegistry = lazy(() => import("./IntegrationRegistry"));
const SiemConnectors = lazy(() => import("./SiemConnectors"));
const SiemFeedback = lazy(() => import("./SiemFeedback"));
const SoarConnectors = lazy(() => import("./SoarConnectors"));
const Webhooks = lazy(() => import("./Webhooks"));
const CicdPipeline = lazy(() => import("./CicdPipeline"));

const tabs = [
  { id: "registry", label: "Integration Registry", icon: Network as ComponentType<{ className?: string }>, component: IntegrationRegistry },
  { id: "siem", label: "SIEM Connectors", icon: Database as ComponentType<{ className?: string }>, component: SiemConnectors },
  { id: "feedback", label: "SIEM Feedback", icon: MessageSquare as ComponentType<{ className?: string }>, component: SiemFeedback },
  { id: "soar", label: "SOAR Connectors", icon: Workflow as ComponentType<{ className?: string }>, component: SoarConnectors },
  { id: "webhooks", label: "Webhooks", icon: Webhook as ComponentType<{ className?: string }>, component: Webhooks },
  { id: "cicd", label: "CI/CD Pipeline", icon: GitBranch as ComponentType<{ className?: string }>, component: CicdPipeline },
];

export default function IntegrationsHub() {
  return (
    <AppShell activePath="/siem-connectors">
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Webhook className="h-6 w-6 text-primary" />
            Integrations
          </h1>
          <p className="text-muted-foreground mt-1">
            Integration registry, SIEM, SOAR, webhook, and CI/CD pipeline integrations
          </p>
        </div>
        <HubTabs tabs={tabs} storageKey="integrations-hub" />
      </div>
    </AppShell>
  );
}
