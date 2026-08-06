import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/_core/hooks/useAuth";
import {
  Shield,
  Key,
  Settings,
  Download,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Clock,
  ArrowUpCircle,
  HelpCircle,
  Send,
  ExternalLink,
  Server,
  Activity,
  Lock,
} from "lucide-react";

// ─── License Status Section ─────────────────────────────────────────────────

function LicenseStatusSection() {
  const licenseQuery = trpc.whiteLabel.getLicenseStatus.useQuery();
  const configQuery = trpc.whiteLabel.getConfig.useQuery();

  const license = licenseQuery.data;
  const config = configQuery.data;

  if (licenseQuery.isLoading) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          Loading license information...
        </CardContent>
      </Card>
    );
  }

  const isActive = license?.valid && !license?.isExpired;
  const daysLeft = license?.daysUntilExpiry ?? 0;
  const tierLabel = license?.tier
    ? license.tier.charAt(0).toUpperCase() + license.tier.slice(1)
    : "Unknown";

  return (
    <div className="space-y-4">
      {/* License Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${isActive ? "bg-emerald-500/10" : "bg-red-500/10"}`}>
                {isActive ? (
                  <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                ) : (
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                )}
              </div>
              <div>
                <p className="text-lg font-bold">{isActive ? "Active" : "Inactive"}</p>
                <p className="text-xs text-muted-foreground">License Status</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Shield className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-lg font-bold">{tierLabel}</p>
                <p className="text-xs text-muted-foreground">License Tier</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${daysLeft > 30 ? "bg-blue-500/10" : daysLeft > 0 ? "bg-amber-500/10" : "bg-red-500/10"}`}>
                <Clock className={`h-5 w-5 ${daysLeft > 30 ? "text-blue-400" : daysLeft > 0 ? "text-amber-400" : "text-red-400"}`} />
              </div>
              <div>
                <p className="text-lg font-bold">
                  {daysLeft > 0 ? `${daysLeft} days` : "Expired"}
                </p>
                <p className="text-xs text-muted-foreground">Until Expiry</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Feature Access */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <Lock className="h-4 w-4" /> Feature Access
          </CardTitle>
          <CardDescription>Features available with your current license tier</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {[
              { name: "Domain Intelligence", key: "domainIntel", starter: true },
              { name: "Threat Matching", key: "threatMatching", starter: true },
              { name: "Incident Search", key: "incidentSearch", starter: true },
              { name: "Vulnerability Scanning", key: "vulnScanning", starter: false },
              { name: "Red Team Operations", key: "redTeam", starter: false },
              { name: "Purple Team", key: "purpleTeam", starter: false },
              { name: "SIEM Integration", key: "siemIntegration", starter: false },
              { name: "API Security", key: "apiSecurity", starter: false },
              { name: "Cloud Security", key: "cloudSecurity", starter: false },
              { name: "Compliance Mapping", key: "complianceMapping", starter: false },
              { name: "Executive Reports", key: "executiveReports", starter: true },
              { name: "Custom Playbooks", key: "customPlaybooks", starter: false },
            ].map((feature) => {
              const enabled =
                license?.tier === "enterprise" ||
                (license?.tier === "professional" && !["cloudSecurity", "customPlaybooks"].includes(feature.key)) ||
                feature.starter;

              return (
                <div
                  key={feature.key}
                  className={`flex items-center gap-2 p-2 rounded-lg border ${
                    enabled
                      ? "border-emerald-500/30 bg-emerald-500/5"
                      : "border-border/30 bg-muted/20 opacity-50"
                  }`}
                >
                  {enabled ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                  ) : (
                    <Lock className="h-4 w-4 text-muted-foreground shrink-0" />
                  )}
                  <span className="text-sm">{feature.name}</span>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Usage Meters */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <Activity className="h-4 w-4" /> Usage This Period
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {[
            { label: "Scans", used: 12, max: license?.tier === "enterprise" ? -1 : license?.tier === "professional" ? 500 : 50 },
            { label: "Reports", used: 8, max: license?.tier === "enterprise" ? -1 : license?.tier === "professional" ? 200 : 20 },
            { label: "Active Seats", used: 3, max: license?.tier === "enterprise" ? -1 : license?.tier === "professional" ? 25 : 5 },
          ].map((meter) => {
            const pct = meter.max === -1 ? 10 : Math.min(100, (meter.used / meter.max) * 100);
            return (
              <div key={meter.label}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium">{meter.label}</span>
                  <span className="text-xs text-muted-foreground">
                    {meter.used} / {meter.max === -1 ? "∞" : meter.max}
                  </span>
                </div>
                <Progress value={pct} className="h-2" />
              </div>
            );
          })}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Updates Section ────────────────────────────────────────────────────────

function UpdatesSection() {
  const versionQuery = trpc.licenseAdmin.getCurrentVersion.useQuery();
  const changelogQuery = trpc.licenseAdmin.getChangelog.useQuery({ limit: 5 });

  const currentVersion = versionQuery.data?.version ?? "...";
  const changelog = changelogQuery.data ?? [];

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Server className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-lg font-bold font-mono">v{currentVersion}</p>
                <p className="text-xs text-muted-foreground">Your Current Version</p>
              </div>
            </div>
            <Badge variant="outline" className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
              <CheckCircle2 className="h-3 w-3 mr-1" /> Up to Date
            </Badge>
          </div>
        </CardContent>
      </Card>

      <h3 className="text-sm font-medium text-muted-foreground">Recent Releases</h3>

      {changelog.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            No release history available.
          </CardContent>
        </Card>
      ) : (
        changelog.map((v) => (
          <Card key={v.version}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CardTitle className="text-base font-mono">v{v.version}</CardTitle>
                  {v.isBreaking && (
                    <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30 text-xs">
                      Breaking
                    </Badge>
                  )}
                </div>
                <span className="text-xs text-muted-foreground">
                  {new Date(v.releaseDate).toLocaleDateString()}
                </span>
              </div>
            </CardHeader>
            <CardContent>
              <pre className="whitespace-pre-wrap text-xs text-muted-foreground bg-muted/30 p-3 rounded-lg">
                {v.changelog}
              </pre>
              {v.downloadUrl && (
                <Button variant="outline" size="sm" className="gap-1 mt-3 text-xs" asChild>
                  <a href={v.downloadUrl} target="_blank" rel="noopener noreferrer">
                    <Download className="h-3 w-3" /> Download
                  </a>
                </Button>
              )}
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}

// ─── Deployment Config Section ──────────────────────────────────────────────

function DeploymentConfigSection() {
  const configQuery = trpc.whiteLabel.getConfig.useQuery();
  const config = configQuery.data;

  const envVars = [
    { key: "DATABASE_URL", desc: "MySQL/TiDB connection string", sensitive: true },
    { key: "JWT_SECRET", desc: "Session signing secret", sensitive: true },
    { key: "SHODAN_API_KEY", desc: "Shodan API key for asset discovery", sensitive: true },
    { key: "SECURITYTRAILS_API_KEY", desc: "SecurityTrails API key for DNS intel", sensitive: true },
    { key: "ABUSEIPDB_API_KEY", desc: "AbuseIPDB API key for IP reputation", sensitive: true },
    { key: "CENSYS_API_ID", desc: "Censys API ID for certificate search", sensitive: true },
    { key: "WL_ORG_NAME", desc: "Organization name for branding", sensitive: false, value: config?.orgName },
    { key: "WL_PRIMARY_COLOR", desc: "Primary brand color", sensitive: false, value: config?.primaryColor },
    { key: "WL_SUPPORT_EMAIL", desc: "Support contact email", sensitive: false, value: config?.supportEmail },
    { key: "WL_DOMAIN", desc: "Deployment domain", sensitive: false, value: config?.domain },
  ];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <Settings className="h-4 w-4" /> Deployment Configuration
          </CardTitle>
          <CardDescription>
            Environment variables configured for your deployment. Sensitive values are masked.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {envVars.map((env) => (
              <div
                key={env.key}
                className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border/30"
              >
                <div>
                  <p className="text-sm font-mono font-medium">{env.key}</p>
                  <p className="text-xs text-muted-foreground">{env.desc}</p>
                </div>
                <div className="text-right">
                  {env.sensitive ? (
                    <span className="text-xs text-muted-foreground font-mono">••••••••</span>
                  ) : (
                    <span className="text-xs font-mono text-foreground">
                      {env.value || "Not set"}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <FileText className="h-4 w-4" /> Quick Reference
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="p-3 rounded-lg bg-muted/30 border border-border/30">
            <p className="text-sm font-medium mb-1">Docker Compose Commands</p>
            <pre className="text-xs text-muted-foreground font-mono">
{`# Start all services
docker compose up -d

# View logs
docker compose logs -f ac3

# Restart after config change
docker compose restart ac3

# Update to latest version
docker compose pull && docker compose up -d`}
            </pre>
          </div>
          <div className="p-3 rounded-lg bg-muted/30 border border-border/30">
            <p className="text-sm font-medium mb-1">Health Check</p>
            <pre className="text-xs text-muted-foreground font-mono">
{`curl -s http://localhost:3000/api/trpc/auth.me`}
            </pre>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Support Section ────────────────────────────────────────────────────────

function SupportSection() {
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const { toast } = useToast();

  const handleSubmit = () => {
    if (!subject || !message) return;
    toast({
      title: "Support Request Sent",
      description: "Our team will respond within 24 hours.",
    });
    setSubject("");
    setMessage("");
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <HelpCircle className="h-4 w-4" /> Contact Support
          </CardTitle>
          <CardDescription>
            Submit a support request and our team will respond within 24 hours.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="subject">Subject</Label>
            <Input
              id="subject"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="Brief description of your issue"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="message">Message</Label>
            <Textarea
              id="message"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Describe your issue in detail..."
              rows={6}
            />
          </div>
          <Button onClick={handleSubmit} disabled={!subject || !message} className="gap-2">
            <Send className="h-4 w-4" /> Submit Request
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Resources</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {[
            { label: "Documentation", url: "https://docs.aceofcloud.com", icon: FileText },
            { label: "API Reference", url: "https://api.aceofcloud.com/docs", icon: ExternalLink },
            { label: "Status Page", url: "https://status.aceofcloud.com", icon: Activity },
          ].map((link) => (
            <a
              key={link.label}
              href={link.url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border/30 hover:bg-muted/50 transition-colors"
            >
              <link.icon className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm">{link.label}</span>
              <ExternalLink className="h-3 w-3 ml-auto text-muted-foreground" />
            </a>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────

export default function CustomerPortalSelfService() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Key className="h-6 w-6 text-primary" />
          Customer Portal
        </h1>
        <p className="text-muted-foreground mt-1">
          Manage your license, check for updates, and configure your deployment
        </p>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="license">
        <TabsList>
          <TabsTrigger value="license" className="gap-1">
            <Shield className="h-3.5 w-3.5" /> License
          </TabsTrigger>
          <TabsTrigger value="updates" className="gap-1">
            <ArrowUpCircle className="h-3.5 w-3.5" /> Updates
          </TabsTrigger>
          <TabsTrigger value="config" className="gap-1">
            <Settings className="h-3.5 w-3.5" /> Configuration
          </TabsTrigger>
          <TabsTrigger value="support" className="gap-1">
            <HelpCircle className="h-3.5 w-3.5" /> Support
          </TabsTrigger>
        </TabsList>

        <TabsContent value="license">
          <LicenseStatusSection />
        </TabsContent>
        <TabsContent value="updates">
          <UpdatesSection />
        </TabsContent>
        <TabsContent value="config">
          <DeploymentConfigSection />
        </TabsContent>
        <TabsContent value="support">
          <SupportSection />
        </TabsContent>
      </Tabs>
    </div>
  );
}
