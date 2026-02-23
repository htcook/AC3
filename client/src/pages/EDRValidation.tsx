import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import {
  ShieldCheck, Plus, Search, RefreshCw, Activity, Target,
  CheckCircle2, XCircle, AlertTriangle, Zap
} from "lucide-react";

export default function EDRValidation() {
  const [activeTab, setActiveTab] = useState("catalog");
  const [searchQuery, setSearchQuery] = useState("");
  const [showAddProduct, setShowAddProduct] = useState(false);
  const [newProduct, setNewProduct] = useState({
    productName: "",
    vendor: "",
    version: "",
    deploymentType: "endpoint" as "endpoint" | "network" | "cloud" | "hybrid",
  });

  const catalog = trpc.edrValidation.getTestCatalog.useQuery({});
  const products = trpc.edrValidation.listProducts.useQuery({});
  const stats = trpc.edrValidation.getStats.useQuery();

  const addProductMut = trpc.edrValidation.addProduct.useMutation({
    onSuccess: () => {
      toast.success("EDR product added.");
      setShowAddProduct(false);
      products.refetch();
      stats.refetch();
    },
    onError: (err: { message: string }) => toast.error(err.message),
  });

  const filteredCatalog = useMemo(() => {
    if (!catalog.data) return [] as NonNullable<typeof catalog.data>["tests"];
    let items = [...catalog.data.tests];
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      items = items.filter((t) =>
        t.testName.toLowerCase().includes(q) || t.description.toLowerCase().includes(q)
      );
    }
    return items;
  }, [catalog.data, searchQuery]);

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <ShieldCheck className="h-7 w-7 text-green-400" />
              EDR Effectiveness Validation
            </h1>
            <p className="text-muted-foreground mt-1">
              Test endpoint detection & response products against real attack techniques
            </p>
          </div>
          <div className="flex gap-2">
            <Dialog open={showAddProduct} onOpenChange={setShowAddProduct}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm">
                  <Plus className="h-4 w-4 mr-1" /> Add EDR Product
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Add EDR Product</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label>Product Name</Label>
                    <Input value={newProduct.productName} onChange={(e) => setNewProduct(p => ({ ...p, productName: e.target.value }))} placeholder="CrowdStrike Falcon" />
                  </div>
                  <div>
                    <Label>Vendor</Label>
                    <Input value={newProduct.vendor} onChange={(e) => setNewProduct(p => ({ ...p, vendor: e.target.value }))} placeholder="CrowdStrike" />
                  </div>
                  <div>
                    <Label>Version</Label>
                    <Input value={newProduct.version} onChange={(e) => setNewProduct(p => ({ ...p, version: e.target.value }))} placeholder="7.x" />
                  </div>
                  <div>
                    <Label>Deployment Type</Label>
                    <Select value={newProduct.deploymentType} onValueChange={(v) => setNewProduct(p => ({ ...p, deploymentType: v as typeof newProduct.deploymentType }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="endpoint">Endpoint</SelectItem>
                        <SelectItem value="network">Network</SelectItem>
                        <SelectItem value="cloud">Cloud</SelectItem>
                        <SelectItem value="hybrid">Hybrid</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Button className="w-full" onClick={() => addProductMut.mutate(newProduct)} disabled={addProductMut.isPending || !newProduct.productName}>
                    {addProductMut.isPending ? "Adding..." : "Add Product"}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">EDR Products</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalProducts ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Test Results</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalTestResults ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Catalog Size</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.catalogSize ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Known Products</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.knownProducts ?? 0}</p>
            </CardContent>
          </Card>
        </div>

        {/* Search */}
        <div className="flex gap-3 items-center">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search tests..." className="pl-9" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
          </div>
          <Button variant="outline" size="sm" onClick={() => { catalog.refetch(); products.refetch(); stats.refetch(); }}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="catalog">Test Catalog ({catalog.data?.total ?? 0})</TabsTrigger>
            <TabsTrigger value="coverage">Coverage Matrix</TabsTrigger>
            <TabsTrigger value="products">Products ({products.data?.length ?? 0})</TabsTrigger>
          </TabsList>

          <TabsContent value="catalog" className="space-y-3">
            {filteredCatalog.map((test: (typeof filteredCatalog)[number]) => (
              <Card key={test.id} className="bg-card/50 border-border/50 hover:border-green-500/30 transition-colors">
                <CardContent className="py-4">
                  <div className="flex items-start justify-between">
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="font-semibold text-foreground">{test.testName}</h3>
                        <Badge variant="outline" className="text-xs capitalize">{test.category.replace(/_/g, " ")}</Badge>
                        <Badge variant="outline" className={
                          test.riskLevel === "safe" ? "text-green-400 border-green-500/30" :
                          test.riskLevel === "low" ? "text-blue-400 border-blue-500/30" :
                          test.riskLevel === "medium" ? "text-yellow-400 border-yellow-500/30" :
                          "text-red-400 border-red-500/30"
                        }>{test.riskLevel}</Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">{test.description}</p>
                      <div className="flex gap-1 flex-wrap mt-1">
                        <Badge variant="secondary" className="text-xs font-mono">{test.mitreTechniqueId}</Badge>
                        <Badge variant="secondary" className="text-xs">{test.mitreTechniqueName}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        <span className="text-foreground/70">Expected:</span> {test.expectedBehavior}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            {filteredCatalog.length === 0 && (
              <div className="text-center py-12 text-muted-foreground">
                <Target className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p>No tests match your search</p>
              </div>
            )}
          </TabsContent>

          <TabsContent value="coverage" className="space-y-4">
            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <CardTitle>MITRE ATT&CK Coverage Matrix</CardTitle>
                <CardDescription>Detection effectiveness by ATT&CK category</CardDescription>
              </CardHeader>
              <CardContent>
                {catalog.data?.categories ? (
                  <div className="grid md:grid-cols-3 gap-3">
                    {catalog.data.categories.map((cat: string) => {
                      const catTests = catalog.data!.tests.filter((t) => t.category === cat);
                      return (
                        <div key={cat} className="p-3 rounded-lg border border-border/50 bg-background/50">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-foreground capitalize">{cat.replace(/_/g, " ")}</span>
                            <span className="text-xs text-muted-foreground">{catTests.length} tests</span>
                          </div>
                          <div className="flex gap-1 flex-wrap">
                            {catTests.map((t) => (
                              <Badge key={t.id} variant="secondary" className="text-xs font-mono">{t.mitreTechniqueId}</Badge>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Target className="h-12 w-12 mx-auto mb-3 opacity-40" />
                    <p>Loading coverage matrix...</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="products" className="space-y-3">
            {products.data?.map((product) => (
              <Card key={product.id} className="bg-card/50 border-border/50">
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <ShieldCheck className="h-8 w-8 text-green-400/60" />
                      <div>
                        <h3 className="font-semibold text-foreground">{product.productName}</h3>
                        <p className="text-sm text-muted-foreground">
                          {product.vendor} · v{product.version} · {product.deploymentType}
                        </p>
                      </div>
                    </div>
                    <Badge variant="outline" className={product.status === "active" ? "text-green-400 border-green-500/30" : "text-yellow-400 border-yellow-500/30"}>
                      {product.status}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!products.data || products.data.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <ShieldCheck className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p>No EDR products configured</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => setShowAddProduct(true)}>
                  <Plus className="h-4 w-4 mr-1" /> Add First Product
                </Button>
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
