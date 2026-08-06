import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { trpc } from "@/lib/trpc";
import { CheckCircle2, Loader2, AlertCircle, Shield, Globe, Mail } from "lucide-react";

interface FreeScanModalProps {
  trigger?: React.ReactNode;
  defaultOpen?: boolean;
}

export default function FreeScanModal({ trigger, defaultOpen = false }: FreeScanModalProps) {
  const [open, setOpen] = useState(defaultOpen);
  const [submitted, setSubmitted] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    organization: "",
    jobTitle: "",
    targetDomain: "",
  });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const submitMutation = trpc.freeScan.submit.useMutation({
    onSuccess: () => {
      setSubmitted(true);
    },
  });

  function validate(): boolean {
    const newErrors: Record<string, string> = {};
    if (formData.name.trim().length < 2) newErrors.name = "Name is required";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) newErrors.email = "Valid work email required";
    if (!formData.targetDomain.trim() || !/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(formData.targetDomain.trim())) {
      newErrors.targetDomain = "Enter a valid domain (e.g., example.com)";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!validate()) return;
    submitMutation.mutate({
      name: formData.name.trim(),
      email: formData.email.trim(),
      organization: formData.organization.trim() || undefined,
      jobTitle: formData.jobTitle.trim() || undefined,
      targetDomain: formData.targetDomain.trim().toLowerCase(),
    });
  }

  function handleOpenChange(newOpen: boolean) {
    setOpen(newOpen);
    if (!newOpen) {
      setTimeout(() => {
        setSubmitted(false);
        setFormData({ name: "", email: "", organization: "", jobTitle: "", targetDomain: "" });
        setErrors({});
        submitMutation.reset();
      }, 300);
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        {trigger || (
          <Button size="lg" className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold">
            Get Free Security Scan
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-[520px] bg-zinc-900 border-zinc-700 text-zinc-100">
        {submitted ? (
          <div className="flex flex-col items-center py-8 text-center gap-4">
            <div className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center">
              <Mail className="w-8 h-8 text-emerald-400" />
            </div>
            <DialogHeader>
              <DialogTitle className="text-xl text-zinc-100">Check Your Email</DialogTitle>
              <DialogDescription className="text-zinc-400 mt-2">
                We've sent a verification link to <span className="text-emerald-400 font-medium">{formData.email}</span>.
                Click the link to start your free Domain Intelligence scan of <span className="text-zinc-200 font-medium">{formData.targetDomain}</span>.
                The link expires in 24 hours.
              </DialogDescription>
            </DialogHeader>
            <div className="mt-4 p-3 rounded-md bg-zinc-800 border border-zinc-700 text-sm text-zinc-400">
              <p>Didn't receive it? Check your spam folder or try again in a few minutes.</p>
            </div>
            <Button
              variant="outline"
              className="mt-2 border-zinc-600 text-zinc-300 hover:bg-zinc-800"
              onClick={() => handleOpenChange(false)}
            >
              Close
            </Button>
          </div>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle className="text-xl text-zinc-100 flex items-center gap-2">
                <Shield className="w-5 h-5 text-emerald-400" />
                Free Domain Intelligence Scan
              </DialogTitle>
              <DialogDescription className="text-zinc-400">
                Get a comprehensive security assessment of your domain — DNS analysis, subdomain discovery, SSL/TLS audit, open ports, and threat exposure. Results delivered in minutes.
              </DialogDescription>
            </DialogHeader>

            <form onSubmit={handleSubmit} className="space-y-4 mt-4">
              {/* Domain field - most prominent */}
              <div className="space-y-2">
                <Label htmlFor="scan-domain" className="text-zinc-300 text-sm font-medium flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-emerald-400" />
                  Domain to Scan *
                </Label>
                <Input
                  id="scan-domain"
                  placeholder="yourcompany.com"
                  value={formData.targetDomain}
                  onChange={(e) => setFormData(prev => ({ ...prev, targetDomain: e.target.value }))}
                  className="bg-zinc-800 border-zinc-600 text-zinc-100 placeholder:text-zinc-500 focus:border-emerald-500 text-lg h-12"
                  autoFocus
                />
                {errors.targetDomain && <p className="text-red-400 text-xs">{errors.targetDomain}</p>}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="scan-name" className="text-zinc-300 text-sm">Full Name *</Label>
                  <Input
                    id="scan-name"
                    placeholder="Jane Smith"
                    value={formData.name}
                    onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                    className="bg-zinc-800 border-zinc-600 text-zinc-100 placeholder:text-zinc-500 focus:border-emerald-500"
                  />
                  {errors.name && <p className="text-red-400 text-xs">{errors.name}</p>}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="scan-email" className="text-zinc-300 text-sm">Work Email *</Label>
                  <Input
                    id="scan-email"
                    type="email"
                    placeholder="jane@company.com"
                    value={formData.email}
                    onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
                    className="bg-zinc-800 border-zinc-600 text-zinc-100 placeholder:text-zinc-500 focus:border-emerald-500"
                  />
                  {errors.email && <p className="text-red-400 text-xs">{errors.email}</p>}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="scan-org" className="text-zinc-300 text-sm">Organization</Label>
                  <Input
                    id="scan-org"
                    placeholder="Acme Inc."
                    value={formData.organization}
                    onChange={(e) => setFormData(prev => ({ ...prev, organization: e.target.value }))}
                    className="bg-zinc-800 border-zinc-600 text-zinc-100 placeholder:text-zinc-500 focus:border-emerald-500"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="scan-title" className="text-zinc-300 text-sm">Job Title</Label>
                  <Input
                    id="scan-title"
                    placeholder="CISO, VP Security"
                    value={formData.jobTitle}
                    onChange={(e) => setFormData(prev => ({ ...prev, jobTitle: e.target.value }))}
                    className="bg-zinc-800 border-zinc-600 text-zinc-100 placeholder:text-zinc-500 focus:border-emerald-500"
                  />
                </div>
              </div>

              {submitMutation.error && (
                <div className="flex items-center gap-2 p-3 rounded-md bg-red-500/10 border border-red-500/30">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                  <p className="text-red-400 text-sm">{submitMutation.error.message}</p>
                </div>
              )}

              <div className="flex justify-end gap-3 pt-2">
                <Button
                  type="button"
                  variant="outline"
                  className="border-zinc-600 text-zinc-300 hover:bg-zinc-800"
                  onClick={() => handleOpenChange(false)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={submitMutation.isPending}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold min-w-[160px]"
                >
                  {submitMutation.isPending ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Submitting...
                    </>
                  ) : (
                    "Start Free Scan"
                  )}
                </Button>
              </div>

              <div className="flex items-center gap-4 pt-2 text-xs text-zinc-500 justify-center">
                <span className="flex items-center gap-1"><Shield className="w-3 h-3" /> Passive scan only</span>
                <span>•</span>
                <span>No login required</span>
                <span>•</span>
                <span>Results in 2-5 min</span>
              </div>
            </form>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
