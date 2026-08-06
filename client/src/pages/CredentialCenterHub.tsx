import AppShell from "@/components/AppShell";
import HubTabs from "@/components/HubTabs";
import { KeyRound, AlertTriangle, RefreshCw } from "lucide-react";
import React, { lazy } from "react";

const CloudCredentials = lazy(() => import("./CloudCredentials"));
const CredentialAlerts = lazy(() => import("./CredentialAlerts"));
const CredentialAutoRotation = lazy(() => import("./CredentialAutoRotation"));

export default function CredentialCenterHub() {
  return (
    <AppShell activePath="/cloud-credentials">
      <div className="flex flex-col gap-4">
        <div className="flex items-center gap-2">
          <KeyRound className="w-6 h-6" />
          <h1 className="text-2xl font-display tracking-wider">Credential Center</h1>
        </div>
        <p className="text-muted-foreground">
          Cloud credentials, alerts, and automated rotation
        </p>
        <HubTabs
          storageKey="credential-center"
          tabs={[
            {
              id: "credentials",
              label: "Cloud Credentials",
              icon: KeyRound,
              component: CloudCredentials,
            },
            {
              id: "alerts",
              label: "Credential Alerts",
              icon: AlertTriangle,
              component: CredentialAlerts,
            },
            {
              id: "rotation",
              label: "Auto-Rotation",
              icon: RefreshCw,
              component: CredentialAutoRotation,
            },
          ]}
        />
      </div>
    </AppShell>
  );
}
