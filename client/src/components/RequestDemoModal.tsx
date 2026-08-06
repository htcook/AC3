import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
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
import { CheckCircle2, Loader2, AlertCircle } from "lucide-react";

interface RequestDemoModalProps {
  trigger?: React.ReactNode;
  defaultOpen?: boolean;
}

export default function RequestDemoModal({ trigger, defaultOpen = false }: RequestDemoModalProps) {
  const [open, setOpen] = useState(defaultOpen);
  const [submitted, setSubmitted] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    organization: "",
    jobTitle: "",
    useCase: "",
  });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const submitMutation = trpc.demoRequests.submit.useMutation({
    onSuccess: () => {
      setSubmitted(true);
    },
  });

  function validate(): boolean {
    const newErrors: Record<string, string> = {};
    if (formData.name.trim().length < 2) newErrors.name = "Name must be at least 2 characters";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) newErrors.email = "Please enter a valid email";
    if (formData.organization.trim().length < 2) newErrors.organization = "Organization is required";
    if (formData.useCase.trim().length < 10) newErrors.useCase = "Please describe your use case (at least 10 characters)";
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!validate()) return;
    submitMutation.mutate({
      name: formData.name.trim(),
      email: formData.email.trim(),
      organization: formData.organization.trim(),
      jobTitle: formData.jobTitle.trim() || undefined,
      useCase: formData.useCase.trim(),
    });
  }

  function handleOpenChange(newOpen: boolean) {
    setOpen(newOpen);
    if (!newOpen) {
      // Reset form when closing
      setTimeout(() => {
        setSubmitted(false);
        setFormData({ name: "", email: "", organization: "", jobTitle: "", useCase: "" });
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
            Request Early Access
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-[500px] bg-zinc-900 border-zinc-700 text-zinc-100">
        {submitted ? (
          <div className="flex flex-col items-center py-8 text-center gap-4">
            <div className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center">
              <CheckCircle2 className="w-8 h-8 text-emerald-400" />
            </div>
            <DialogHeader>
              <DialogTitle className="text-xl text-zinc-100">Demo Request Received</DialogTitle>
              <DialogDescription className="text-zinc-400 mt-2">
                Thank you for your interest in AC3. We'll reach out within 1-2 business days to schedule your personalized demo.
              </DialogDescription>
            </DialogHeader>
            <Button
              variant="outline"
              className="mt-4 border-zinc-600 text-zinc-300 hover:bg-zinc-800"
              onClick={() => handleOpenChange(false)}
            >
              Close
            </Button>
          </div>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle className="text-xl text-zinc-100">Request a Demo</DialogTitle>
              <DialogDescription className="text-zinc-400">
                See how AC3 can transform your offensive security operations. Fill out the form below and we'll schedule a personalized walkthrough.
              </DialogDescription>
            </DialogHeader>

            <form onSubmit={handleSubmit} className="space-y-4 mt-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="demo-name" className="text-zinc-300 text-sm">Full Name *</Label>
                  <Input
                    id="demo-name"
                    placeholder="Jane Smith"
                    value={formData.name}
                    onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                    className="bg-zinc-800 border-zinc-600 text-zinc-100 placeholder:text-zinc-500 focus:border-emerald-500"
                  />
                  {errors.name && <p className="text-red-400 text-xs">{errors.name}</p>}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="demo-email" className="text-zinc-300 text-sm">Work Email *</Label>
                  <Input
                    id="demo-email"
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
                  <Label htmlFor="demo-org" className="text-zinc-300 text-sm">Organization *</Label>
                  <Input
                    id="demo-org"
                    placeholder="Acme Security Inc."
                    value={formData.organization}
                    onChange={(e) => setFormData(prev => ({ ...prev, organization: e.target.value }))}
                    className="bg-zinc-800 border-zinc-600 text-zinc-100 placeholder:text-zinc-500 focus:border-emerald-500"
                  />
                  {errors.organization && <p className="text-red-400 text-xs">{errors.organization}</p>}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="demo-title" className="text-zinc-300 text-sm">Job Title</Label>
                  <Input
                    id="demo-title"
                    placeholder="CISO, VP Security, etc."
                    value={formData.jobTitle}
                    onChange={(e) => setFormData(prev => ({ ...prev, jobTitle: e.target.value }))}
                    className="bg-zinc-800 border-zinc-600 text-zinc-100 placeholder:text-zinc-500 focus:border-emerald-500"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="demo-usecase" className="text-zinc-300 text-sm">How would you use AC3? *</Label>
                <Textarea
                  id="demo-usecase"
                  placeholder="Tell us about your security testing needs, team size, current tools, and what challenges you're looking to solve..."
                  rows={4}
                  value={formData.useCase}
                  onChange={(e) => setFormData(prev => ({ ...prev, useCase: e.target.value }))}
                  className="bg-zinc-800 border-zinc-600 text-zinc-100 placeholder:text-zinc-500 focus:border-emerald-500 resize-none"
                />
                {errors.useCase && <p className="text-red-400 text-xs">{errors.useCase}</p>}
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
                  className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold min-w-[140px]"
                >
                  {submitMutation.isPending ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Submitting...
                    </>
                  ) : (
                    "Request Demo"
                  )}
                </Button>
              </div>

              <p className="text-zinc-500 text-xs text-center pt-2">
                By submitting, you agree to be contacted about AC3. We respect your privacy and will never share your information.
              </p>
            </form>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
