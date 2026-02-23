import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { PlusCircle, MoreHorizontal, Users, Building, CheckCircle, XCircle } from "lucide-react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";

// Mock data structure for a Tenant, replace with your actual tRPC output type
interface Tenant {
  id: string;
  name: string;
  slug: string;
  isActive: boolean;
  users: number;
  maxUsers: number;
  createdAt: string;
  contactEmail?: string;
  features?: string[];
}

export default function Tenants() {
  const [isCreateDialogOpen, setCreateDialogOpen] = useState(false);
  const [isEditDialogOpen, setEditDialogOpen] = useState(false);
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);

  const { data: stats, isLoading: isLoadingStats } = trpc.tenants.getStats.useQuery();
  const { data: tenants, isLoading: isLoadingTenants, refetch } = trpc.tenants.list.useQuery();

  const createTenantMutation = trpc.tenants.create.useMutation({
    onSuccess: () => {
      toast.success("Tenant created successfully.");
      refetch();
      setCreateDialogOpen(false);
    },
    onError: (error) => {
      toast.error(`Failed to create tenant: ${error.message}`);
    },
  });

  const updateTenantMutation = trpc.tenants.update.useMutation({
    onSuccess: () => {
      toast.success("Tenant updated successfully.");
      refetch();
      setEditDialogOpen(false);
    },
    onError: (error) => {
      toast.error(`Failed to update tenant: ${error.message}`);
    },
  });

  const deleteTenantMutation = trpc.tenants.delete.useMutation({
    onSuccess: () => {
      toast.success("Tenant deleted successfully.");
      refetch();
    },
    onError: (error) => {
      toast.error(`Failed to delete tenant: ${error.message}`);
    },
  });

  const handleCreateTenant = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const data = Object.fromEntries(formData.entries());
    createTenantMutation.mutate({
      name: data.name as string,
      slug: data.slug as string,
      contactEmail: data.contactEmail as string || undefined,
      maxUsers: data.maxUsers ? Number(data.maxUsers) : undefined,
    });
  };

  const handleUpdateTenant = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedTenant) return;
    const formData = new FormData(event.currentTarget);
    const data = Object.fromEntries(formData.entries());
    updateTenantMutation.mutate({
      id: selectedTenant.id,
      name: data.name as string,
      contactEmail: data.contactEmail as string || undefined,
      isActive: data.isActive === "true",
      maxUsers: data.maxUsers ? Number(data.maxUsers) : undefined,
    });
  };

  const handleDeleteTenant = (id: string) => {
    if (window.confirm("Are you sure you want to delete this tenant?")) {
      deleteTenantMutation.mutate({ id });
    }
  };

  const statCards = useMemo(() => [
    { title: "Total Tenants", value: stats?.totalTenants ?? 0, icon: Building },
    { title: "Active Tenants", value: stats?.activeTenants ?? 0, icon: CheckCircle },
    { title: "Total Users", value: stats?.totalUsers ?? 0, icon: Users },
  ], [stats]);

  return (
    <div className="flex flex-col h-full bg-zinc-900 text-white p-8 space-y-6">
      <Card className="bg-slate-900 border-slate-800">
        <CardContent className="pt-6">
          <p className="text-slate-400">This page is for multi-tenancy management. You can create and manage tenant organizations, set user limits, toggle active status, and configure feature access for each tenant.</p>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-3">
        {isLoadingStats ? (
          Array.from({ length: 3 }).map((_, i) => (
            <Card key={i} className="bg-slate-900 border-slate-800 animate-pulse">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium text-slate-400 h-5 w-24 bg-slate-700 rounded"></CardTitle>
                <div className="h-6 w-6 bg-slate-700 rounded"></div>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold h-8 w-12 bg-slate-700 rounded"></div>
              </CardContent>
            </Card>
          ))
        ) : (
          statCards.map(card => (
            <Card key={card.title} className="bg-slate-900 border-slate-800">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium text-slate-400">{card.title}</CardTitle>
                <card.icon className="h-4 w-4 text-slate-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{card.value}</div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      <Card className="flex-grow bg-slate-900 border-slate-800">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Tenants</CardTitle>
          <Dialog open={isCreateDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm" className="gap-1 bg-blue-600 hover:bg-blue-700">
                <PlusCircle className="h-4 w-4" />
                Create Tenant
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[425px] bg-slate-900 border-slate-800 text-white">
              <DialogHeader>
                <DialogTitle>Create New Tenant</DialogTitle>
                <DialogDescription>Fill in the details for the new tenant.</DialogDescription>
              </DialogHeader>
              <form onSubmit={handleCreateTenant}>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="name" className="text-right text-slate-400">Name</Label>
                    <Input id="name" name="name" className="col-span-3 bg-slate-800 border-slate-700" required />
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="slug" className="text-right text-slate-400">Slug</Label>
                    <Input id="slug" name="slug" className="col-span-3 bg-slate-800 border-slate-700" required />
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="contactEmail" className="text-right text-slate-400">Contact Email</Label>
                    <Input id="contactEmail" name="contactEmail" type="email" className="col-span-3 bg-slate-800 border-slate-700" />
                  </div>
                  <div className="grid grid-cols-4 items-center gap-4">
                    <Label htmlFor="maxUsers" className="text-right text-slate-400">Max Users</Label>
                    <Input id="maxUsers" name="maxUsers" type="number" className="col-span-3 bg-slate-800 border-slate-700" />
                  </div>
                </div>
                <DialogFooter>
                  <Button type="submit" disabled={createTenantMutation.isLoading} className="bg-blue-600 hover:bg-blue-700">
                    {createTenantMutation.isLoading ? "Creating..." : "Create Tenant"}
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="border-slate-800 hover:bg-slate-800/50">
                <TableHead className="text-white">Name</TableHead>
                <TableHead className="text-white">Slug</TableHead>
                <TableHead className="text-white">Status</TableHead>
                <TableHead className="text-white">Users</TableHead>
                <TableHead className="text-white">Created</TableHead>
                <TableHead className="text-right text-white">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoadingTenants ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <TableRow key={i} className="border-slate-800 animate-pulse">
                    <TableCell><div className="h-5 w-24 bg-slate-700 rounded"></div></TableCell>
                    <TableCell><div className="h-5 w-20 bg-slate-700 rounded"></div></TableCell>
                    <TableCell><div className="h-5 w-16 bg-slate-700 rounded"></div></TableCell>
                    <TableCell><div className="h-5 w-12 bg-slate-700 rounded"></div></TableCell>
                    <TableCell><div className="h-5 w-28 bg-slate-700 rounded"></div></TableCell>
                    <TableCell className="text-right"><div className="h-5 w-8 bg-slate-700 rounded ml-auto"></div></TableCell>
                  </TableRow>
                ))
              ) : tenants && tenants.length > 0 ? (
                tenants.map((tenant: Tenant) => (
                  <TableRow key={tenant.id} className="border-slate-800 hover:bg-slate-800/50">
                    <TableCell className="font-medium">{tenant.name}</TableCell>
                    <TableCell className="text-slate-400">{tenant.slug}</TableCell>
                    <TableCell>
                      <Badge variant={tenant.isActive ? "default" : "destructive"} className={tenant.isActive ? "bg-green-600/20 text-green-400 border-green-600/50" : "bg-red-600/20 text-red-400 border-red-600/50"}>
                        {tenant.isActive ? "Active" : "Inactive"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span>{tenant.users}/{tenant.maxUsers}</span>
                        <Progress value={(tenant.users / tenant.maxUsers) * 100} className="w-20 h-1.5 bg-slate-700" indicatorClassName="bg-blue-500" />
                      </div>
                    </TableCell>
                    <TableCell>{new Date(tenant.createdAt).toLocaleDateString()}</TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" onClick={() => { setSelectedTenant(tenant); setEditDialogOpen(true); }}>
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow className="border-slate-800">
                  <TableCell colSpan={6} className="text-center text-slate-500 py-12">
                    <Building className="mx-auto h-12 w-12 text-slate-600" />
                    <p className="mt-4">No tenants found.</p>
                    <p className="text-sm text-slate-600">Get started by creating a new tenant.</p>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {selectedTenant && (
        <Dialog open={isEditDialogOpen} onOpenChange={setEditDialogOpen}>
          <DialogContent className="sm:max-w-[425px] bg-slate-900 border-slate-800 text-white">
            <DialogHeader>
              <DialogTitle>Edit Tenant: {selectedTenant.name}</DialogTitle>
              <DialogDescription>Update the details for this tenant.</DialogDescription>
            </DialogHeader>
            <form onSubmit={handleUpdateTenant}>
              <div className="grid gap-4 py-4">
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="edit-name" className="text-right text-slate-400">Name</Label>
                  <Input id="edit-name" name="name" defaultValue={selectedTenant.name} className="col-span-3 bg-slate-800 border-slate-700" required />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="edit-contactEmail" className="text-right text-slate-400">Contact Email</Label>
                  <Input id="edit-contactEmail" name="contactEmail" type="email" defaultValue={selectedTenant.contactEmail} className="col-span-3 bg-slate-800 border-slate-700" />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="edit-maxUsers" className="text-right text-slate-400">Max Users</Label>
                  <Input id="edit-maxUsers" name="maxUsers" type="number" defaultValue={selectedTenant.maxUsers} className="col-span-3 bg-slate-800 border-slate-700" />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="edit-isActive" className="text-right text-slate-400">Status</Label>
                  <Select name="isActive" defaultValue={String(selectedTenant.isActive)}>
                    <SelectTrigger className="col-span-3 bg-slate-800 border-slate-700">
                      <SelectValue placeholder="Select status" />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-800 text-white border-slate-700">
                      <SelectItem value="true">Active</SelectItem>
                      <SelectItem value="false">Inactive</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter className="justify-between">
                <Button type="button" variant="destructive" onClick={() => handleDeleteTenant(selectedTenant.id)} disabled={deleteTenantMutation.isLoading}>
                  {deleteTenantMutation.isLoading ? "Deleting..." : "Delete"}
                </Button>
                <Button type="submit" disabled={updateTenantMutation.isLoading} className="bg-blue-600 hover:bg-blue-700">
                  {updateTenantMutation.isLoading ? "Saving..." : "Save Changes"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}
