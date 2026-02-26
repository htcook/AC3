import AppShell from "@/components/AppShell";
import WorkflowLauncher from "@/components/WorkflowLauncher";

export default function Workflows() {
  return (
    <AppShell activePath="/workflows">
      <div className="p-4 sm:p-6">
        <WorkflowLauncher />
      </div>
    </AppShell>
  );
}
