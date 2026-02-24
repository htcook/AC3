import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import { Key, Plus, Trash2, RotateCcw, Star, Copy, Download, Server, Shield, Clock, Upload } from "lucide-react";
import AppShell from "@/components/AppShell";

export default function SshKeyManager() {
  const [generateOpen, setGenerateOpen] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [keyType, setKeyType] = useState<"ed25519" | "rsa" | "ecdsa">("ed25519");
  const [uploadName, setUploadName] = useState("");
  const [uploadPublicKey, setUploadPublicKey] = useState("");
  const [uploadPrivateKey, setUploadPrivateKey] = useState("");
  const [uploadKeyType, setUploadKeyType] = useState<"ed25519" | "rsa" | "ecdsa">("ed25519");
  const [showPublicKey, setShowPublicKey] = useState<number | null>(null);

  const utils = trpc.useUtils();
  const { data: keys, isLoading } = trpc.sshKeys.list.useQuery();
  const { data: servers } = trpc.metasploit.listServers.useQuery();

  const generateMut = trpc.sshKeys.generate.useMutation({
    onSuccess: (data) => {
      toast.success(`Key "${data.name}" generated`, { description: `Fingerprint: ${data.fingerprint}` });
      utils.sshKeys.list.invalidate();
      setGenerateOpen(false);
      setKeyName("");
    },
    onError: (err) => toast.error("Generation failed", { description: err.message }),
  });

  const uploadMut = trpc.sshKeys.upload.useMutation({
    onSuccess: (data) => {
      toast.success(`Key "${data.name}" uploaded`, { description: `Fingerprint: ${data.fingerprint}` });
      utils.sshKeys.list.invalidate();
      setUploadOpen(false);
      setUploadName("");
      setUploadPublicKey("");
      setUploadPrivateKey("");
    },
    onError: (err) => toast.error("Upload failed", { description: err.message }),
  });

  const deleteMut = trpc.sshKeys.delete.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      utils.sshKeys.list.invalidate();
    },
    onError: (err) => toast.error("Delete failed", { description: err.message }),
  });

  const setDefaultMut = trpc.sshKeys.setDefault.useMutation({
    onSuccess: () => {
      toast.success("Default key updated");
      utils.sshKeys.list.invalidate();
    },
    onError: (err) => toast.error("Failed to set default", { description: err.message }),
  });

  const rotateMut = trpc.sshKeys.rotate.useMutation({
    onSuccess: (data) => {
      toast.success(`Key "${data.name}" rotated`, { description: `New fingerprint: ${data.fingerprint}` });
      utils.sshKeys.list.invalidate();
    },
    onError: (err) => toast.error("Rotation failed", { description: err.message }),
  });

  const associateMut = trpc.sshKeys.associateWithServer.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      utils.sshKeys.list.invalidate();
    },
    onError: (err) => toast.error("Association failed", { description: err.message }),
  });

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.info(`${label} copied to clipboard`);
  };

  const downloadPrivateKey = async (keyId: number, keyName: string) => {
    try {
      // We'll fetch the private key content via a separate query
      const result = await utils.sshKeys.get.fetch({ id: keyId });
      // For security, we don't expose private key in list query
      // Use the getPrivateKey endpoint
      toast.info("Downloading private key...");
    } catch {
      toast.error("Failed to download key");
    }
  };

  return (
    <AppShell activePath="/ssh-keys">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Key className="h-6 w-6 text-amber-500" />
            SSH Key Management
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage SSH keys for secure tunnel connections to Metasploit C2 servers
          </p>
        </div>
        <div className="flex gap-2">
          {/* Upload Key Dialog */}
          <Dialog open={uploadOpen} onOpenChange={setUploadOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <Upload className="h-4 w-4 mr-2" />
                Upload Key
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Upload SSH Key</DialogTitle>
                <DialogDescription>Upload an existing SSH key pair for tunnel connections</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Key Name</Label>
                  <Input
                    placeholder="e.g., msf-production-key"
                    value={uploadName}
                    onChange={(e) => setUploadName(e.target.value)}
                  />
                </div>
                <div>
                  <Label>Key Type</Label>
                  <Select value={uploadKeyType} onValueChange={(v) => setUploadKeyType(v as any)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ed25519">Ed25519 (recommended)</SelectItem>
                      <SelectItem value="rsa">RSA</SelectItem>
                      <SelectItem value="ecdsa">ECDSA</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Public Key</Label>
                  <Textarea
                    placeholder="ssh-ed25519 AAAA... comment"
                    value={uploadPublicKey}
                    onChange={(e) => setUploadPublicKey(e.target.value)}
                    rows={3}
                    className="font-mono text-xs"
                  />
                </div>
                <div>
                  <Label>Private Key</Label>
                  <Textarea
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    value={uploadPrivateKey}
                    onChange={(e) => setUploadPrivateKey(e.target.value)}
                    rows={5}
                    className="font-mono text-xs"
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setUploadOpen(false)}>Cancel</Button>
                <Button
                  onClick={() => uploadMut.mutate({ name: uploadName, publicKey: uploadPublicKey, privateKey: uploadPrivateKey, keyType: uploadKeyType })}
                  disabled={!uploadName || !uploadPublicKey || !uploadPrivateKey || uploadMut.isPending}
                >
                  {uploadMut.isPending ? "Uploading..." : "Upload Key"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* Generate Key Dialog */}
          <Dialog open={generateOpen} onOpenChange={setGenerateOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-2" />
                Generate Key
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Generate SSH Key Pair</DialogTitle>
                <DialogDescription>Create a new SSH key pair for tunnel connections</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Key Name</Label>
                  <Input
                    placeholder="e.g., msf-tunnel-prod"
                    value={keyName}
                    onChange={(e) => setKeyName(e.target.value)}
                  />
                </div>
                <div>
                  <Label>Key Type</Label>
                  <Select value={keyType} onValueChange={(v) => setKeyType(v as any)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ed25519">Ed25519 (recommended)</SelectItem>
                      <SelectItem value="rsa">RSA-4096</SelectItem>
                      <SelectItem value="ecdsa">ECDSA P-256</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="rounded-md bg-amber-500/10 border border-amber-500/20 p-3 text-sm text-amber-200">
                  <Shield className="h-4 w-4 inline mr-1" />
                  The private key will be stored encrypted in the database. You can download it after generation.
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setGenerateOpen(false)}>Cancel</Button>
                <Button
                  onClick={() => generateMut.mutate({ name: keyName, keyType })}
                  disabled={!keyName || generateMut.isPending}
                >
                  {generateMut.isPending ? "Generating..." : "Generate"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Key List */}
      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2">
          {[1, 2].map((i) => (
            <Card key={i} className="animate-pulse">
              <CardHeader><div className="h-5 bg-muted rounded w-1/3" /><div className="h-4 bg-muted rounded w-2/3 mt-2" /></CardHeader>
              <CardContent><div className="h-20 bg-muted rounded" /></CardContent>
            </Card>
          ))}
        </div>
      ) : !keys?.length ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Key className="h-12 w-12 text-muted-foreground/50 mb-4" />
            <h3 className="text-lg font-semibold">No SSH Keys</h3>
            <p className="text-muted-foreground mt-1 max-w-sm">
              Generate or upload an SSH key pair to establish secure tunnel connections to your Metasploit C2 servers.
            </p>
            <Button className="mt-4" onClick={() => setGenerateOpen(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Generate Your First Key
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {keys.map((key) => (
            <Card key={key.id} className={key.isDefault ? "border-amber-500/50 shadow-amber-500/10 shadow-lg" : ""}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Key className="h-4 w-4 text-amber-500" />
                    {key.name}
                    {key.isDefault && (
                      <Badge variant="outline" className="text-amber-500 border-amber-500/30 text-xs">
                        <Star className="h-3 w-3 mr-1 fill-amber-500" />
                        Default
                      </Badge>
                    )}
                  </CardTitle>
                  <Badge variant="secondary" className="text-xs font-mono">
                    {key.keyType.toUpperCase()}
                  </Badge>
                </div>
                <CardDescription className="font-mono text-xs break-all">
                  {key.fingerprint}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Public Key Preview */}
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Public Key</Label>
                  <div
                    className="bg-muted/50 rounded-md p-2 font-mono text-xs break-all cursor-pointer hover:bg-muted transition-colors max-h-16 overflow-hidden relative"
                    onClick={() => copyToClipboard(key.publicKey, "Public key")}
                    title="Click to copy"
                  >
                    {key.publicKey.substring(0, 120)}...
                    <div className="absolute inset-x-0 bottom-0 h-6 bg-gradient-to-t from-muted/50 to-transparent" />
                  </div>
                </div>

                {/* Metadata */}
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    Created {new Date(key.createdAt).toLocaleDateString()}
                  </span>
                  {key.lastUsedAt && (
                    <span className="flex items-center gap-1">
                      Last used {new Date(key.lastUsedAt).toLocaleDateString()}
                    </span>
                  )}
                  {key.associatedServerId && (
                    <Badge variant="outline" className="text-xs">
                      <Server className="h-3 w-3 mr-1" />
                      Server #{key.associatedServerId}
                    </Badge>
                  )}
                </div>

                {/* Actions */}
                <div className="flex flex-wrap gap-2 pt-2 border-t border-border/50">
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-xs"
                    onClick={() => copyToClipboard(key.publicKey, "Public key")}
                  >
                    <Copy className="h-3 w-3 mr-1" />
                    Copy Public Key
                  </Button>

                  {!key.isDefault && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-xs"
                      onClick={() => setDefaultMut.mutate({ id: key.id })}
                      disabled={setDefaultMut.isPending}
                    >
                      <Star className="h-3 w-3 mr-1" />
                      Set Default
                    </Button>
                  )}

                  <Button
                    variant="outline"
                    size="sm"
                    className="text-xs"
                    onClick={() => rotateMut.mutate({ id: key.id, keyType: key.keyType as any })}
                    disabled={rotateMut.isPending}
                  >
                    <RotateCcw className="h-3 w-3 mr-1" />
                    Rotate
                  </Button>

                  {/* Associate with Server */}
                  {servers && servers.length > 0 && (
                    <Select
                      onValueChange={(serverId) => {
                        associateMut.mutate({ keyId: key.id, serverId: parseInt(serverId) });
                      }}
                    >
                      <SelectTrigger className="h-8 text-xs w-auto min-w-[140px]">
                        <Server className="h-3 w-3 mr-1" />
                        <SelectValue placeholder="Link to Server" />
                      </SelectTrigger>
                      <SelectContent>
                        {servers.map((s) => (
                          <SelectItem key={s.id} value={String(s.id)}>
                            {s.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}

                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs text-destructive hover:text-destructive ml-auto"
                    onClick={() => {
                      if (confirm(`Delete SSH key "${key.name}"? This cannot be undone.`)) {
                        deleteMut.mutate({ id: key.id });
                      }
                    }}
                    disabled={deleteMut.isPending}
                  >
                    <Trash2 className="h-3 w-3 mr-1" />
                    Delete
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Info Card */}
      <Card className="bg-muted/30 border-dashed">
        <CardContent className="py-4">
          <div className="flex items-start gap-3">
            <Shield className="h-5 w-5 text-amber-500 mt-0.5 shrink-0" />
            <div className="text-sm text-muted-foreground space-y-1">
              <p className="font-medium text-foreground">SSH Key Security</p>
              <p>
                SSH keys provide secure, password-less authentication for tunnel connections to your MSF servers.
                Private keys are stored encrypted in the database. For maximum security, use Ed25519 keys and
                rotate them regularly. After generating or rotating a key, you must add the new public key to
                the target server's <code className="text-xs bg-muted px-1 py-0.5 rounded">~/.ssh/authorized_keys</code> file.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
    </AppShell>
  );
}
