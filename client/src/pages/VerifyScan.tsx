import { useEffect, useState } from "react";
import { useParams } from "wouter";
import { trpc } from "@/lib/trpc";
import { CheckCircle2, Loader2, XCircle, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function VerifyScan() {
  const { token } = useParams<{ token: string }>();
  const [status, setStatus] = useState<"verifying" | "success" | "error">("verifying");
  const [errorMessage, setErrorMessage] = useState("");
  const [scanToken, setScanToken] = useState("");

  const verifyMutation = trpc.freeScan.verifyEmail.useMutation({
    onSuccess: (data) => {
      setStatus("success");
      setScanToken(data.scanToken);
    },
    onError: (err) => {
      setStatus("error");
      setErrorMessage(err.message || "Verification failed. The link may have expired.");
    },
  });

  useEffect(() => {
    if (token) {
      verifyMutation.mutate({ token });
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        {/* Logo */}
        <div className="flex items-center justify-center gap-2 mb-8">
          <Shield className="w-8 h-8 text-emerald-400" />
          <span className="text-2xl font-display tracking-wider text-zinc-100">AC3</span>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-8 text-center">
          {status === "verifying" && (
            <div className="flex flex-col items-center gap-4">
              <Loader2 className="w-12 h-12 text-emerald-400 animate-spin" />
              <h2 className="text-xl font-semibold text-zinc-100">Verifying your email...</h2>
              <p className="text-zinc-400 text-sm">This will only take a moment.</p>
            </div>
          )}

          {status === "success" && (
            <div className="flex flex-col items-center gap-4">
              <div className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center">
                <CheckCircle2 className="w-8 h-8 text-emerald-400" />
              </div>
              <h2 className="text-xl font-semibold text-zinc-100">Email Verified!</h2>
              <p className="text-zinc-400 text-sm">
                Your Domain Intelligence scan has been queued. Results will be ready in 2-5 minutes.
              </p>
              <div className="mt-4 p-3 rounded-md bg-zinc-800 border border-zinc-700 text-sm text-zinc-300 w-full">
                <p>You'll receive an email with your results, or you can bookmark this link:</p>
                <a
                  href={`/scan-results/${scanToken}`}
                  className="text-emerald-400 hover:text-emerald-300 underline mt-2 block break-all"
                >
                  View Scan Results
                </a>
              </div>
              <Button
                className="mt-4 bg-emerald-600 hover:bg-emerald-500 text-white"
                onClick={() => window.location.href = `/scan-results/${scanToken}`}
              >
                Go to Results Page
              </Button>
            </div>
          )}

          {status === "error" && (
            <div className="flex flex-col items-center gap-4">
              <div className="w-16 h-16 rounded-full bg-red-500/20 flex items-center justify-center">
                <XCircle className="w-8 h-8 text-red-400" />
              </div>
              <h2 className="text-xl font-semibold text-zinc-100">Verification Failed</h2>
              <p className="text-zinc-400 text-sm">{errorMessage}</p>
              <Button
                variant="outline"
                className="mt-4 border-zinc-600 text-zinc-300 hover:bg-zinc-800"
                onClick={() => window.location.href = "/"}
              >
                Return to Homepage
              </Button>
            </div>
          )}
        </div>

        <p className="text-center text-zinc-600 text-xs mt-6">
          Ace of Cloud &middot; Autonomous Cybersecurity Command Center
        </p>
      </div>
    </div>
  );
}
