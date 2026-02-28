import React, { ComponentType, lazy, LazyExoticComponent } from "react";
import AppShell from "@/components/AppShell";
import HubTabs from "@/components/HubTabs";
import { FileText, Briefcase, BarChart3, Copy } from "lucide-react";

const ReportGenerator = lazy(() => import("./ReportGenerator"));
const PostEngagementReport = lazy(() => import("./PostEngagementReport"));
const BiaReport = lazy(() => import("./BiaReport"));
const ReportTemplates = lazy(() => import("./ReportTemplates"));

const tabs: {
  id: string;
  label: string;
  icon?: ComponentType<{ className?: string }>;
  component: LazyExoticComponent<ComponentType<any>> | ComponentType<any>;
}[] = [
  {
    id: "generator",
    label: "Report Generator",
    icon: FileText,
    component: ReportGenerator,
  },
  {
    id: "engagement",
    label: "Engagement Report",
    icon: Briefcase,
    component: PostEngagementReport,
  },
  {
    id: "bia",
    label: "BIA Report",
    icon: BarChart3,
    component: BiaReport,
  },
  {
    id: "templates",
    label: "Templates",
    icon: Copy,
    component: ReportTemplates,
  },
];

const ReportsHub = () => {
  return (
    <AppShell activePath="/reports/generate">
      <div className="w-full">
        <div className="flex items-center space-x-2">
          <FileText className="h-6 w-6" />
          <h1 className="font-display text-2xl font-bold tracking-wider">
            Reports
          </h1>
        </div>
        <p className="mt-2 text-gray-500">
          Report generation, engagement reports, BIA, and templates
        </p>
        <div className="mt-4">
          <HubTabs tabs={tabs} storageKey="reports-hub" />
        </div>
      </div>
    </AppShell>
  );
};

export default ReportsHub;
