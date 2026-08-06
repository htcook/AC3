import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { Database, Search, Loader2, AlertTriangle, ShieldAlert, Info } from "lucide-react";
import AppShell from "@/components/AppShell";

const severityColors: Record<string, string> = {
  CRITICAL: "bg-red-500 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-blue-500 text-white",
};

export default function NvdCveMatcher() {
  const [cveId, setCveId] = useState("");
  const [vendor, setVendor] = useState("");
  const [product, setProduct] = useState("");
  const [version, setVersion] = useState("");
  const [cveResult, setCveResult] = useState<any>(null);
  const [productResult, setProductResult] = useState<any>(null);

  const statusQuery = trpc.nvdCveMatcher.getStatus.useQuery();

  const lookupMut = trpc.nvdCveMatcher.lookupCve.useQuery(
    { cveId: cveId.toUpperCase() },
    { enabled: false }
  );

  const matchMut = trpc.nvdCveMatcher.matchProduct.useQuery(
    { vendor, product, version: version || undefined },
    { enabled: false }
  );

  const handleCveLookup = async () => {
    if (!cveId.trim()) { toast.error("Enter a CVE ID"); return; }
    const result = await lookupMut.refetch();
    if (result.data) setCveResult(result.data);
  };

  const handleProductMatch = async () => {
    if (!vendor.trim() || !product.trim()) { toast.error("Enter vendor and product"); return; }
    const result = await matchMut.refetch();
    if (result.data) setProductResult(result.data);
  };

  return (
    <AppShell activePath="/nvd-cve-matcher">
      <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Database className="h-6 w-6 text-purple-500" />
          Dynamic CVE-to-Product Matching
        </h1>
        <p className="text-muted-foreground mt-1">
          Real-time NVD API integration eliminates stale hardcoded CPE mappings.
        </p>
      </div>

      {/* NVD API Status */}
      {statusQuery.data && (
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-4">
              <div className={`w-3 h-3 rounded-full ${statusQuery.data.hasApiKey ? "bg-green-500" : "bg-yellow-500"}`} />
              <span className="text-sm font-medium">NVD API: {statusQuery.data.hasApiKey ? "API Key Configured" : "No API Key (rate limited)"}</span>
              <Badge variant="outline">Cache: {statusQuery.data.cacheSize} entries</Badge>
              <span className="text-xs text-muted-foreground">TTL: {Math.round(statusQuery.data.cacheTtlMs / 60000)}min</span>
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="cve-lookup">
        <TabsList>
          <TabsTrigger value="cve-lookup">CVE Lookup</TabsTrigger>
          <TabsTrigger value="product-match">Product Match</TabsTrigger>
        </TabsList>

        <TabsContent value="cve-lookup" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>CVE Lookup</CardTitle>
              <CardDescription>Look up a CVE ID to get full vulnerability details and affected products</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-3">
                <Input
                  placeholder="CVE-2021-44228"
                  value={cveId}
                  onChange={e => setCveId(e.target.value)}
                  className="max-w-xs"
                />
                <Button onClick={handleCveLookup} disabled={lookupMut.isFetching}>
                  {lookupMut.isFetching ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Search className="h-4 w-4 mr-2" />}
                  Lookup
                </Button>
              </div>

              {cveResult && (
                <div className="space-y-4 mt-4">
                  <div className="flex items-center gap-3">
                    <h3 className="text-lg font-bold">{cveResult.cveId}</h3>
                    {cveResult.severity && (
                      <Badge className={severityColors[cveResult.severity] || "bg-zinc-500"}>
                        {cveResult.severity}
                      </Badge>
                    )}
                    {cveResult.cvssScore && (
                      <Badge variant="outline">CVSS {cveResult.cvssScore}</Badge>
                    )}
                  </div>
                  {cveResult.description && (
                    <p className="text-sm text-muted-foreground">{cveResult.description}</p>
                  )}
                  {cveResult.affectedProducts && cveResult.affectedProducts.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Affected Products ({cveResult.affectedProducts.length})</h4>
                      <div className="space-y-1 max-h-60 overflow-y-auto">
                        {cveResult.affectedProducts.map((p: any, i: number) => (
                          <div key={i} className="flex items-center gap-2 p-2 rounded border text-sm">
                            <Badge variant="outline">{p.vendor}</Badge>
                            <span>{p.product}</span>
                            {p.versionRange && <span className="text-muted-foreground">{p.versionRange}</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {cveResult.references && cveResult.references.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">References</h4>
                      <div className="space-y-1">
                        {cveResult.references.slice(0, 5).map((ref: any, i: number) => (
                          <a key={i} href={ref.url} target="_blank" rel="noopener noreferrer"
                            className="block text-sm text-blue-500 hover:underline truncate">{ref.url}</a>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="product-match" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Product Match</CardTitle>
              <CardDescription>Find all CVEs affecting a specific product and version</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <Input placeholder="Vendor (e.g., apache)" value={vendor} onChange={e => setVendor(e.target.value)} />
                <Input placeholder="Product (e.g., log4j)" value={product} onChange={e => setProduct(e.target.value)} />
                <Input placeholder="Version (optional)" value={version} onChange={e => setVersion(e.target.value)} />
              </div>
              <Button onClick={handleProductMatch} disabled={matchMut.isFetching}>
                {matchMut.isFetching ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Search className="h-4 w-4 mr-2" />}
                Match
              </Button>

              {productResult && productResult.matches && (
                <div className="space-y-3 mt-4">
                  <div className="flex items-center gap-3">
                    <h3 className="font-bold">{productResult.matches.length} CVEs found</h3>
                    {productResult.criticalCount > 0 && (
                      <Badge className="bg-red-500 text-white">
                        <ShieldAlert className="h-3 w-3 mr-1" />{productResult.criticalCount} Critical
                      </Badge>
                    )}
                  </div>
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {productResult.matches.map((m: any, i: number) => (
                      <div key={i} className="flex items-center justify-between p-3 rounded border">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm font-medium">{m.cveId}</span>
                          <Badge className={severityColors[m.severity] || "bg-zinc-500"} >{m.severity}</Badge>
                        </div>
                        <div className="flex items-center gap-2">
                          {m.cvssScore && <Badge variant="outline">CVSS {m.cvssScore}</Badge>}
                          {m.hasExploit && <Badge variant="destructive">Exploit Available</Badge>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
    </AppShell>
  );
}
