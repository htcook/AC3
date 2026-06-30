/**
 * Compatibility shim for `useToast` hook.
 * Wraps sonner's `toast` so legacy imports from `@/hooks/use-toast` keep working.
 * Supports both sonner-style `toast("message")` and shadcn-style `toast({ title, description })`.
 */
import { toast as sonnerToast } from "sonner";

interface ToastOptions {
  title?: string;
  description?: string;
  variant?: string;
  [key: string]: any;
}

function toast(msgOrOpts: string | ToastOptions, opts?: any) {
  if (typeof msgOrOpts === "string") {
    return sonnerToast(msgOrOpts, opts);
  }
  const { title, description, variant } = msgOrOpts;
  if (variant === "destructive") {
    return sonnerToast.error(title || "Error", { description });
  }
  return sonnerToast(title || "", { description });
}

export function useToast() {
  return { toast };
}
