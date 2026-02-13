import { Link, useLocation } from "wouter";
import { useState } from "react";
import {
  Cloud, Activity, Key, Target, Cpu, Zap, Users, FileText, BookOpen, Fish,
  Menu, X, LogOut, Shield, Globe2, Server, HardDrive, Mail, Lock,
  ArrowRight, ArrowDown, Download, Copy, Check, Network, Terminal,
  Briefcase,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { ENGAGEMENT_INFRA, INFRA_REQUIREMENTS } from "@/data/compliance-data";

import AppShell from "@/components/AppShell";
export default function InfraReference() {
  const [, navigate] = useLocation();
  const [copied, setCopied] = useState(false);

  const iconMap: Record<string, React.ReactNode> = {
    "Bastion": <Lock className="w-6 h-6" />,
    "App Server": <Server className="w-6 h-6" />,
    "Mail Server": <Mail className="w-6 h-6" />,
    "Log Sink": <HardDrive className="w-6 h-6" />,
  };

  const colorMap: Record<string, string> = {
    "Bastion": "text-yellow-400 border-yellow-500/30",
    "App Server": "text-primary border-primary/30",
    "Mail Server": "text-purple-400 border-purple-500/30",
    "Log Sink": "text-blue-400 border-blue-500/30",
  };

  const copyTfvars = () => {
    const template = `# terraform.tfvars - Engagement Configuration
do_token             = "dop_v1_XXXX"
engagement_id        = "clientx-2026q1"
region               = "nyc3"
ssh_key_fingerprints = ["XX:XX:XX:XX"]
redteam_admin_cidrs  = ["YOUR.IP.HERE/32"]
app_https_cidrs      = ["0.0.0.0/0", "::/0"]`;
    navigator.clipboard.writeText(template);
    setCopied(true);
    toast.success("tfvars template copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <AppShell activePath="/infra-reference">
{/* Sidebar */}
<header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4">
            <h1 className="font-display text-3xl md:text-2xl sm:text-3xl lg:text-4xl">ENGAGEMENT INFRASTRUCTURE</h1>
            <p className="text-sm text-muted-foreground">Terraform-provisioned isolated DigitalOcean VPC architecture for per-engagement red team infrastructure with hardened firewall rules.</p>
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">

          {/* Architecture Diagram */}
          <section>
            <h2 className="font-display text-2xl mb-4">NETWORK ARCHITECTURE</h2>
            <div className="bg-card border-2 border-border p-6">
              {/* VPC Container */}
              <div className="border-2 border-dashed border-primary/30 p-6 relative">
                <div className="absolute -top-3 left-4 bg-card px-3">
                  <span className="font-display text-xs tracking-wider text-primary">ISOLATED VPC — PER-ENGAGEMENT</span>
                </div>

                {/* Top: Red Team Entry */}
                <div className="text-center mb-6">
                  <div className="inline-flex items-center gap-2 bg-red-500/10 border border-red-500/30 px-4 py-2">
                    <Network className="w-4 h-4 text-red-400" />
                    <span className="font-display text-sm tracking-wider text-red-400">RED TEAM OPERATORS</span>
                  </div>
                  <div className="flex justify-center my-2">
                    <ArrowDown className="w-5 h-5 text-red-400 animate-pulse" />
                  </div>
                  <div className="text-[10px] text-muted-foreground tracking-wider">SSH (APPROVED CIDRs ONLY)</div>
                </div>

                {/* Bastion */}
                <div className="flex justify-center mb-6">
                  <div className="bg-card border-2 border-yellow-500/30 p-4 w-64 text-center">
                    <Lock className="w-8 h-8 text-yellow-400 mx-auto mb-2" />
                    <div className="font-display text-lg text-yellow-400">BASTION</div>
                    <div className="text-xs text-muted-foreground">Jump Host • SSH Only</div>
                    <div className="text-[10px] text-muted-foreground mt-1">s-1vcpu-1gb</div>
                  </div>
                </div>

                {/* Arrows from Bastion */}
                <div className="flex justify-center mb-2">
                  <div className="flex items-center gap-4 sm:p-6 lg:p-8">
                    <ArrowDown className="w-5 h-5 text-yellow-400" />
                    <ArrowDown className="w-5 h-5 text-yellow-400" />
                    <ArrowDown className="w-5 h-5 text-yellow-400" />
                  </div>
                </div>
                <div className="text-center text-[10px] text-muted-foreground tracking-wider mb-4">PRIVATE IP SSH ONLY</div>

                {/* Three droplets */}
                <div className="grid md:grid-cols-3 gap-4">
                  <div className="bg-card border-2 border-primary/30 p-4 text-center">
                    <Server className="w-8 h-8 text-primary mx-auto mb-2" />
                    <div className="font-display text-lg text-primary">APP SERVER</div>
                    <div className="text-xs text-muted-foreground">C2 / Caldera / GoPhish</div>
                    <div className="text-[10px] text-muted-foreground mt-1">s-2vcpu-2gb</div>
                    <div className="mt-2 px-2 py-1 bg-primary/10 text-[10px] tracking-wider text-primary">HTTPS 443 EXPOSED</div>
                  </div>
                  <div className="bg-card border-2 border-purple-500/30 p-4 text-center">
                    <Mail className="w-8 h-8 text-purple-400 mx-auto mb-2" />
                    <div className="font-display text-lg text-purple-400">MAIL SERVER</div>
                    <div className="text-xs text-muted-foreground">SMTP Relay (Outbound)</div>
                    <div className="text-[10px] text-muted-foreground mt-1">s-1vcpu-1gb</div>
                    <div className="mt-2 px-2 py-1 bg-purple-500/10 text-[10px] tracking-wider text-purple-400">NO INBOUND SMTP</div>
                  </div>
                  <div className="bg-card border-2 border-blue-500/30 p-4 text-center">
                    <HardDrive className="w-8 h-8 text-blue-400 mx-auto mb-2" />
                    <div className="font-display text-lg text-blue-400">LOG SINK</div>
                    <div className="text-xs text-muted-foreground">Centralized Logging</div>
                    <div className="text-[10px] text-muted-foreground mt-1">s-1vcpu-1gb + 50GB Vol</div>
                    <div className="mt-2 px-2 py-1 bg-blue-500/10 text-[10px] tracking-wider text-blue-400">SYSLOG 6514 FROM VPC</div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* Component Details */}
          <section>
            <h2 className="font-display text-2xl mb-4">COMPONENT DETAILS</h2>
            <div className="space-y-4">
              {ENGAGEMENT_INFRA.map((comp) => (
                <div key={comp.name} className={`bg-card border-2 ${colorMap[comp.name]} p-5`}>
                  <div className="flex items-start gap-4">
                    <div className={colorMap[comp.name].split(' ')[0]}>
                      {iconMap[comp.name]}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className={`font-display text-lg ${colorMap[comp.name].split(' ')[0]}`}>{comp.name.toUpperCase()}</h3>
                        <span className="px-2 py-0.5 text-[10px] font-display tracking-wider bg-secondary text-muted-foreground">{comp.role}</span>
                        <span className="px-2 py-0.5 text-[10px] font-display tracking-wider bg-secondary text-muted-foreground">{comp.size}</span>
                      </div>
                      <p className="text-sm text-muted-foreground mb-2">{comp.description}</p>
                      <div className="bg-secondary/50 px-3 py-2">
                        <p className="text-xs"><span className="font-display tracking-wider text-muted-foreground">ACCESS: </span>{comp.access}</p>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* Terraform Setup */}
          <section>
            <h2 className="font-display text-2xl mb-4">TERRAFORM DEPLOYMENT</h2>
            <div className="grid md:grid-cols-2 gap-4">
              {/* Requirements */}
              <div className="bg-card border-2 border-border p-5">
                <h3 className="font-display text-lg mb-3 text-primary">REQUIREMENTS</h3>
                <div className="space-y-2 mb-4">
                  <div className="flex items-center gap-2 bg-secondary/50 p-2">
                    <Terminal className="w-4 h-4 text-primary" />
                    <span className="text-sm">Terraform {INFRA_REQUIREMENTS.terraform}</span>
                  </div>
                  <div className="flex items-center gap-2 bg-secondary/50 p-2">
                    <Cloud className="w-4 h-4 text-primary" />
                    <span className="text-sm">{INFRA_REQUIREMENTS.provider}</span>
                  </div>
                  {INFRA_REQUIREMENTS.tools.map(t => (
                    <div key={t} className="flex items-center gap-2 bg-secondary/50 p-2">
                      <Terminal className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm font-mono">{t}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Variables */}
              <div className="bg-card border-2 border-border p-5">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-display text-lg text-primary">TERRAFORM VARIABLES</h3>
                  <Button variant="outline" size="sm" className="text-xs" onClick={copyTfvars}>
                    {copied ? <Check className="w-3 h-3 mr-1" /> : <Copy className="w-3 h-3 mr-1" />}
                    COPY TFVARS
                  </Button>
                </div>
                <div className="space-y-2">
                  {INFRA_REQUIREMENTS.variables.map(v => (
                    <div key={v.name} className="flex items-center justify-between bg-secondary/50 p-2">
                      <div className="flex items-center gap-2">
                        {v.sensitive && <Lock className="w-3 h-3 text-red-400" />}
                        <span className="text-sm font-mono">{v.name}</span>
                      </div>
                      <span className="text-xs text-muted-foreground">{v.description}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Deploy Commands */}
            <div className="mt-4 bg-card border-2 border-border p-5">
              <h3 className="font-display text-lg mb-3 text-primary">DEPLOYMENT COMMANDS</h3>
              <div className="bg-black/50 p-4 font-mono text-sm space-y-1">
                <p className="text-muted-foreground"># Initialize Terraform</p>
                <p className="text-green-400">$ terraform init</p>
                <p className="text-muted-foreground mt-2"># Plan and review changes</p>
                <p className="text-green-400">$ terraform plan</p>
                <p className="text-muted-foreground mt-2"># Apply infrastructure</p>
                <p className="text-green-400">$ terraform apply</p>
                <p className="text-muted-foreground mt-2"># Validate firewall rules</p>
                <p className="text-green-400">$ ./scripts/validate_firewalls.sh &lt;engagement_id&gt;</p>
                <p className="text-muted-foreground mt-2"># Destroy after engagement</p>
                <p className="text-red-400">$ terraform destroy</p>
              </div>
            </div>
          </section>

        </div>
    </AppShell>
  );
}

