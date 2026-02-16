import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { 
  Cloud, 
  Activity, 
  Key,
  Users,
  Copy,
  Eye,
  EyeOff,
  LogOut,
  Menu,
  X,
  Target,
  FileText,
  Terminal,
  Lock,
  ExternalLink,
  Zap,
  Cpu,
  Fish,
  BookOpen,
  Shield,
  Globe2,
  Briefcase,
} from "lucide-react";
import { useState, useEffect } from "react";

import AppShell from "@/components/AppShell";
// Credentials data - DigitalOcean Caldera Server
const CREDENTIALS = {
  adminLogin: {
    username: 'admin',
    password: 'PVYedK$BUAYzyXaAegdEl2Dz',
  },
  redApiKey: 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e',
  blueApiKey: '16498a3a0320fefc58083406f86d2de08f6f3735c537e72e6ae481ee8dd6cb7d',
  sshCommand: 'ssh -i ~/.ssh/caldera_do_key root@137.184.7.224',
  serverUrl: 'https://dashboard.aceofcloud.io',
  httpUrl: 'https://caldera.aceofcloud.io',
};

// GoPhish credentials
const GOPHISH_CREDENTIALS = {
  adminLogin: {
    username: 'admin',
    password: 'ADMIN123',
  },
  apiKey: '186292e5e312962ad1fdfc9ecbc21453e6073daf6554861371bd4da0fa61a5a2',
  adminUrl: 'https://gophish.aceofcloud.io',
};

export default function Credentials() {
  const [, navigate] = useLocation();
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  const togglePassword = (key: string) => {
    setShowPasswords(prev => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <AppShell activePath="/credentials">
{/* Sidebar */}
<header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4">
            <h1 className="font-display text-3xl md:text-2xl sm:text-3xl lg:text-4xl">CREDENTIALS</h1>
            <p className="text-sm text-muted-foreground">Secure access credentials for Caldera server and GoPhish</p>
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">
          {/* Admin Login */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <Lock className="w-6 h-6 text-primary" />
              ADMIN LOGIN
            </h2>
            <div className="bg-card border-2 border-border p-6 space-y-4">
              <CredentialRow
                label="USERNAME"
                value={CREDENTIALS.adminLogin.username}
                onCopy={() => copyToClipboard(CREDENTIALS.adminLogin.username, 'Username')}
              />
              <CredentialRow
                label="PASSWORD"
                value={CREDENTIALS.adminLogin.password}
                isSecret
                show={showPasswords['password']}
                onToggle={() => togglePassword('password')}
                onCopy={() => copyToClipboard(CREDENTIALS.adminLogin.password, 'Password')}
              />
              <div className="pt-4">
                <a href={CREDENTIALS.httpUrl} target="_blank" rel="noopener noreferrer">
                  <Button className="font-display tracking-wider bg-primary hover:bg-primary/90">
                    <ExternalLink className="w-4 h-4 mr-2" />
                    OPEN CALDERA LOGIN
                  </Button>
                </a>
              </div>
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* API Keys */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <Key className="w-6 h-6 text-primary" />
              API KEYS
            </h2>
            <div className="grid md:grid-cols-2 gap-4">
              <div className="bg-card border-2 border-border p-6">
                <h3 className="font-display text-lg mb-4 text-red-500">RED TEAM API KEY</h3>
                <CredentialRow
                  label="API KEY"
                  value={CREDENTIALS.redApiKey}
                  isSecret
                  show={showPasswords['redApi']}
                  onToggle={() => togglePassword('redApi')}
                  onCopy={() => copyToClipboard(CREDENTIALS.redApiKey, 'Red Team API Key')}
                />
              </div>
              <div className="bg-card border-2 border-border p-6">
                <h3 className="font-display text-lg mb-4 text-blue-500">BLUE TEAM API KEY</h3>
                <CredentialRow
                  label="API KEY"
                  value={CREDENTIALS.blueApiKey}
                  isSecret
                  show={showPasswords['blueApi']}
                  onToggle={() => togglePassword('blueApi')}
                  onCopy={() => copyToClipboard(CREDENTIALS.blueApiKey, 'Blue Team API Key')}
                />
              </div>
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* SSH Access */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <Terminal className="w-6 h-6 text-primary" />
              SSH ACCESS
            </h2>
            <div className="bg-card border-2 border-border p-6">
              <CredentialRow
                label="SSH COMMAND"
                value={CREDENTIALS.sshCommand}
                onCopy={() => copyToClipboard(CREDENTIALS.sshCommand, 'SSH Command')}
                mono
              />
              <p className="mt-4 text-sm text-muted-foreground">
                Note: SSH key is stored at <code className="bg-secondary px-2 py-1">~/.ssh/caldera_do_key</code>
              </p>
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* Server URLs */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <ExternalLink className="w-6 h-6 text-primary" />
              SERVER URLS
            </h2>
            <div className="bg-card border-2 border-border p-6 space-y-4">
              <CredentialRow
                label="HTTPS URL"
                value={CREDENTIALS.serverUrl}
                onCopy={() => copyToClipboard(CREDENTIALS.serverUrl, 'HTTPS URL')}
                mono
              />
              <CredentialRow
                label="HTTP URL"
                value={CREDENTIALS.httpUrl}
                onCopy={() => copyToClipboard(CREDENTIALS.httpUrl, 'HTTP URL')}
                mono
              />
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* GoPhish Credentials */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <Fish className="w-6 h-6 text-emerald-500" />
              GOPHISH ADMIN
            </h2>
            <div className="bg-card border-2 border-emerald-500/30 p-6 space-y-4">
              <CredentialRow
                label="ADMIN URL"
                value={GOPHISH_CREDENTIALS.adminUrl}
                onCopy={() => copyToClipboard(GOPHISH_CREDENTIALS.adminUrl, 'GoPhish Admin URL')}
                mono
              />
              <CredentialRow
                label="USERNAME"
                value={GOPHISH_CREDENTIALS.adminLogin.username}
                onCopy={() => copyToClipboard(GOPHISH_CREDENTIALS.adminLogin.username, 'GoPhish Username')}
              />
              <CredentialRow
                label="PASSWORD"
                value={GOPHISH_CREDENTIALS.adminLogin.password}
                isSecret
                show={showPasswords['gophishPassword']}
                onToggle={() => togglePassword('gophishPassword')}
                onCopy={() => copyToClipboard(GOPHISH_CREDENTIALS.adminLogin.password, 'GoPhish Password')}
              />
              <div className="w-full h-px bg-border my-2" />
              <h3 className="font-display text-lg text-emerald-500">GOPHISH API KEY</h3>
              <CredentialRow
                label="API KEY"
                value={GOPHISH_CREDENTIALS.apiKey}
                isSecret
                show={showPasswords['gophishApi']}
                onToggle={() => togglePassword('gophishApi')}
                onCopy={() => copyToClipboard(GOPHISH_CREDENTIALS.apiKey, 'GoPhish API Key')}
              />
              <div className="pt-4">
                <a href={GOPHISH_CREDENTIALS.adminUrl} target="_blank" rel="noopener noreferrer">
                  <Button className="font-display tracking-wider bg-emerald-500 hover:bg-emerald-500/90 text-black">
                    <ExternalLink className="w-4 h-4 mr-2" />
                    OPEN GOPHISH ADMIN
                  </Button>
                </a>
              </div>
            </div>
          </section>
        </div>
    </AppShell>
  );
}

function CredentialRow({ 
  label, 
  value, 
  isSecret, 
  show, 
  onToggle, 
  onCopy,
  mono 
}: { 
  label: string; 
  value: string; 
  isSecret?: boolean; 
  show?: boolean; 
  onToggle?: () => void; 
  onCopy: () => void;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col md:flex-row md:items-center gap-2 md:gap-4">
      <span className="text-xs tracking-widest text-muted-foreground w-32 shrink-0">{label}</span>
      <div className="flex-1 flex items-center gap-2 bg-secondary px-4 py-3">
        <code className={`flex-1 text-sm ${mono ? 'font-mono' : ''} ${isSecret && !show ? 'tracking-widest' : ''}`}>
          {isSecret && !show ? '••••••••••••••••' : value}
        </code>
        {isSecret && onToggle && (
          <button onClick={onToggle} className="text-muted-foreground hover:text-white transition-colors">
            {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        )}
        <button onClick={onCopy} className="text-muted-foreground hover:text-primary transition-colors">
          <Copy className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
