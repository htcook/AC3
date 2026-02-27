import AppShell from "@/components/AppShell";
import WorkflowLauncher from "@/components/WorkflowLauncher";

export default function Workflows() {
  return (
    <AppShell activePath="/workflows">
      <div className="p-4 sm:p-6 space-y-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Workflows</h1>
          <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Design and manage automated security workflows that chain multiple tools and actions together. Create custom workflows that trigger scans, run analyses, generate reports, and send notifications based on events or schedules. Monitor active workflows and review execution history to ensure reliable automation.</p>
        </div>
        <WorkflowLauncher />
      </div>
    </AppShell>
  );
}
