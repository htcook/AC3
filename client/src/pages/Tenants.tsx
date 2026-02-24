
import React, { useState, useMemo } from 'react';
import { trpc } from '@/lib/trpc';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { MoreHorizontal, PlusCircle, Trash2, UserPlus, XCircle, AlertTriangle, Edit } from 'lucide-react';
import AppShell from "@/components/AppShell";

// Tenant type from the router definition
type Tenant = {
  id: number;
  name: string;
  slug: string;
  logoUrl: string | null;
  primaryColor: string | null;
  plan: string;
  isActive: boolean;
  maxUsers: number;
  createdAt: Date;
  updatedAt: Date;
};

// Member type from the router definition
type Member = {
    id: number;
    tenantId: number;
    userId: string;
    role: string;
    joinedAt: Date;
}

const TenantForm = ({ tenant, onClose }: { tenant?: Tenant | null, onClose: () => void }) => {
  const utils = trpc.useUtils();
  const [name, setName] = useState(tenant?.name || '');
  const [slug, setSlug] = useState(tenant?.slug || '');
  const [plan, setPlan] = useState<'free' | 'pro' | 'enterprise'>(tenant?.plan as any || 'free');

  const createTenantMutation = trpc.tenants.createTenant.useMutation({
    onSuccess: () => {
      utils.tenants.listTenants.invalidate();
      toast.success('Tenant created successfully');
      onClose();
    },
    onError: (error) => {
      toast.error(`Failed to create tenant: ${error.message}`);
    }
  });

  const updateTenantMutation = trpc.tenants.updateTenant.useMutation({
    onSuccess: () => {
      utils.tenants.listTenants.invalidate();
      toast.success('Tenant updated successfully');
      onClose();
    },
    onError: (error) => {
      toast.error(`Failed to update tenant: ${error.message}`);
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (tenant) {
      updateTenantMutation.mutate({ id: tenant.id, name, slug });
    } else {
      createTenantMutation.mutate({ name, slug, plan });
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{tenant ? 'Edit Tenant' : 'Create New Tenant'}</DialogTitle>
        <DialogDescription>
          {tenant ? 'Update the details of the existing tenant.' : 'Fill in the details to create a new tenant.'}
        </DialogDescription>
      </DialogHeader>
      <div className="grid gap-4 py-4">
        <Input placeholder="Tenant Name" value={name} onChange={(e) => setName(e.target.value)} required />
        <Input placeholder="Tenant Slug" value={slug} onChange={(e) => setSlug(e.target.value)} required />
        {!tenant && (
            <Select onValueChange={(value: 'free' | 'pro' | 'enterprise') => setPlan(value)} defaultValue={plan}>
                <SelectTrigger><SelectValue placeholder="Select a plan" /></SelectTrigger>
                <SelectContent>
                    <SelectItem value="free">Free</SelectItem>
                    <SelectItem value="pro">Pro</SelectItem>
                    <SelectItem value="enterprise">Enterprise</SelectItem>
                </SelectContent>
            </Select>
        )}
      </div>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
        <Button type="submit" disabled={createTenantMutation.isPending || updateTenantMutation.isPending}>
          {createTenantMutation.isPending || updateTenantMutation.isPending ? 'Saving...' : 'Save'}
        </Button>
      </DialogFooter>
    </form>
  );
};

const MemberForm = ({ tenantId, onClose }: { tenantId: number, onClose: () => void }) => {
    const utils = trpc.useUtils();
    const [userId, setUserId] = useState(0);
    const [role, setRole] = useState<'owner' | 'admin' | 'operator' | 'viewer'>('operator');

    const addMemberMutation = trpc.tenants.addMember.useMutation({
        onSuccess: () => {
            utils.tenants.listMembers.invalidate({ tenantId });
            toast.success('Member added successfully');
            onClose();
        },
        onError: (error) => {
            toast.error(`Failed to add member: ${error.message}`);
        }
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        addMemberMutation.mutate({ tenantId, userId: Number(userId), role });
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-4">
            <DialogHeader>
                <DialogTitle>Add New Member</DialogTitle>
            </DialogHeader>
            <div className="grid gap-4 py-4">
                <Input type="number" placeholder="User ID" value={userId || ''} onChange={(e) => setUserId(Number(e.target.value))} required />
                <Select onValueChange={(value: 'owner' | 'admin' | 'operator' | 'viewer') => setRole(value)} defaultValue={role}>
                    <SelectTrigger><SelectValue placeholder="Select a role" /></SelectTrigger>
                    <SelectContent>
                        <SelectItem value="owner">Owner</SelectItem>
                        <SelectItem value="admin">Admin</SelectItem>
                        <SelectItem value="member">Member</SelectItem>
                        <SelectItem value="viewer">Viewer</SelectItem>
                    </SelectContent>
                </Select>
            </div>
            <DialogFooter>
                <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
                <Button type="submit" disabled={addMemberMutation.isPending}>
                    {addMemberMutation.isPending ? 'Adding...' : 'Add Member'}
                </Button>
            </DialogFooter>
        </form>
    );
}

export default function TenantsPage() {
  const [isTenantModalOpen, setTenantModalOpen] = useState(false);
  const [isMemberModalOpen, setMemberModalOpen] = useState(false);
  const [editingTenant, setEditingTenant] = useState<Tenant | null>(null);
  const [selectedTenantId, setSelectedTenantId] = useState<number | null>(null);

  const utils = trpc.useUtils();
  const tenantsQuery = trpc.tenants.listTenants.useQuery();
  const membersQuery = trpc.tenants.listMembers.useQuery(
    { tenantId: selectedTenantId! },
    { enabled: !!selectedTenantId }
  );

  const deleteTenantMutation = trpc.tenants.deleteTenant.useMutation({
    onSuccess: (_, { id }) => {
      utils.tenants.listTenants.invalidate();
      if (selectedTenantId === id) {
          setSelectedTenantId(null);
      }
      toast.success('Tenant deleted successfully');
    },
    onError: (error) => {
      toast.error(`Failed to delete tenant: ${error.message}`);
    }
  });

  const removeMemberMutation = trpc.tenants.removeMember.useMutation({
      onSuccess: () => {
          utils.tenants.listMembers.invalidate({ tenantId: selectedTenantId! });
          toast.success('Member removed successfully');
      },
      onError: (error) => {
          toast.error(`Failed to remove member: ${error.message}`);
      }
  });

  const handleOpenTenantModal = (tenant?: Tenant) => {
    setEditingTenant(tenant || null);
    setTenantModalOpen(true);
  };

  const handleCloseTenantModal = () => {
    setTenantModalOpen(false);
    setEditingTenant(null);
  };

  const selectedTenant = useMemo(() => {
      return tenantsQuery.data?.find(t => t.id === selectedTenantId) || null;
  }, [tenantsQuery.data, selectedTenantId]);

  return (
    <AppShell activePath="/tenants">
      <div className="p-4 md:p-8 bg-background text-foreground min-h-screen">
      <header className="flex items-center justify-between mb-6">
        <div>
            <h1 className="text-3xl font-bold">Tenants</h1>
            <p className="text-muted-foreground">Manage tenants, members, and roles for MSSP client isolation.</p>
        </div>
        <Dialog open={isTenantModalOpen} onOpenChange={setTenantModalOpen}>
          <DialogTrigger asChild>
            <Button onClick={() => handleOpenTenantModal()}>
              <PlusCircle className="mr-2 h-4 w-4" /> Create Tenant
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[425px]">
            <TenantForm tenant={editingTenant} onClose={handleCloseTenantModal} />
          </DialogContent>
        </Dialog>
      </header>

      <div className="grid gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>All Tenants</CardTitle>
            <CardDescription>Select a tenant to view and manage its members.</CardDescription>
          </CardHeader>
          <CardContent>
            {tenantsQuery.isLoading && <p>Loading tenants...</p>}
            {tenantsQuery.error && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{tenantsQuery.error.message}</AlertDescription>
              </Alert>
            )}
            {tenantsQuery.data && tenantsQuery.data.length === 0 && (
                <div className="text-center py-8">
                    <p className="text-muted-foreground">No tenants found.</p>
                    <Button variant="link" onClick={() => handleOpenTenantModal()}>Create the first one</Button>
                </div>
            )}
            {tenantsQuery.data && tenantsQuery.data.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Plan</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {tenantsQuery.data.map((tenant) => (
                    <TableRow 
                        key={tenant.id} 
                        onClick={() => setSelectedTenantId(tenant.id)}
                        className={`cursor-pointer ${selectedTenantId === tenant.id ? 'bg-muted/50' : ''}`}
                    >
                      <TableCell className="font-medium">{tenant.name}</TableCell>
                      <TableCell>{tenant.plan}</TableCell>
                      <TableCell><Badge variant={tenant.isActive ? 'default' : 'outline'}>{tenant.isActive ? 'Active' : 'Inactive'}</Badge></TableCell>
                      <TableCell className="text-right">
                        <Button variant="ghost" size="icon" onClick={(e) => { e.stopPropagation(); handleOpenTenantModal(tenant); }}>
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="icon" onClick={(e) => { e.stopPropagation(); deleteTenantMutation.mutate({ id: tenant.id }); }} disabled={deleteTenantMutation.isPending}>
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-3">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
                <CardTitle>Tenant Members</CardTitle>
                <CardDescription>
                    {selectedTenant ? `Members of ${selectedTenant.name}` : 'Select a tenant to see its members'}
                </CardDescription>
            </div>
            {selectedTenant && (
                <Dialog open={isMemberModalOpen} onOpenChange={setMemberModalOpen}>
                    <DialogTrigger asChild>
                        <Button variant="outline" size="sm">
                            <UserPlus className="mr-2 h-4 w-4" /> Add Member
                        </Button>
                    </DialogTrigger>
                    <DialogContent className="sm:max-w-[425px]">
                        <MemberForm tenantId={selectedTenant.id} onClose={() => setMemberModalOpen(false)} />
                    </DialogContent>
                </Dialog>
            )}
          </CardHeader>
          <CardContent>
            {!selectedTenantId && <div className="text-center py-12 text-muted-foreground">Please select a tenant.</div>}
            {selectedTenantId && membersQuery.isLoading && <p>Loading members...</p>}
            {selectedTenantId && membersQuery.error && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{membersQuery.error.message}</AlertDescription>
              </Alert>
            )}
            {selectedTenantId && membersQuery.data && membersQuery.data.length === 0 && (
                <div className="text-center py-12 text-muted-foreground">No members found for this tenant.</div>
            )}
            {selectedTenantId && membersQuery.data && membersQuery.data.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User ID</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Joined</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {membersQuery.data.map((member) => (
                    <TableRow key={member.id}>
                      <TableCell className="font-mono">{member.userId}</TableCell>
                      <TableCell><Badge variant="secondary">{member.role}</Badge></TableCell>
                      <TableCell>{new Date(member.joinedAt).toLocaleDateString()}</TableCell>
                      <TableCell className="text-right">
                        <Button variant="ghost" size="icon" onClick={() => removeMemberMutation.mutate({ id: member.id })} disabled={removeMemberMutation.isPending}>
                          <XCircle className="h-4 w-4 text-destructive" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
    </AppShell>
  );
}
