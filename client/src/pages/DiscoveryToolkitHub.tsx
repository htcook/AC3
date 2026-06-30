import AppShell from "@/components/AppShell";
import HubTabs from "@/components/HubTabs";
import { Globe2, Globe, Activity, Radio } from "lucide-react";
import React, { lazy } from "react";

const SubfinderPage = lazy(() => import("./SubfinderPage"));
const HttpxPage = lazy(() => import("./HttpxPage"));
const NaabuPage = lazy(() => import("./NaabuPage"));

const DiscoveryToolkitHub = () => {
  const tabs = [
    {
      id: "subfinder",
      label: "Subfinder",
      icon: Globe,
      component: SubfinderPage,
    },
    {
      id: "httpx",
      label: "HTTPX Probe",
      icon: Activity,
      component: HttpxPage,
    },
    {
      id: "naabu",
      label: "Naabu Ports",
      icon: Radio,
      component: NaabuPage,
    },
  ];

  return (
    <AppShell activePath="/tools/subfinder">
      <div className="flex items-center space-x-2">
        <Globe2 className="h-6 w-6" />
        <h1 className="font-display text-2xl tracking-wider">Discovery Toolkit</h1>
      </div>
      <p className="text-muted-foreground">Subdomain enumeration, HTTP probing, and port scanning tools</p>
      <HubTabs tabs={tabs} storageKey="discovery-toolkit" />
    </AppShell>
  );
};

export default DiscoveryToolkitHub;
