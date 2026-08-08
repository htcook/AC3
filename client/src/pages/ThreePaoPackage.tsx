"use client";

export default function ThreePaoPackage() {
  return (
    <div className="space-y-6 max-w-6xl">
      <div className="border-b border-gray-800 pb-4">
        <div className="flex items-center gap-2 mb-1">
          <span className="px-2 py-0.5 text-[10px] font-bold bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded">
            AC3-PLUS
          </span>
        </div>
        <h2 className="text-2xl font-bold tracking-wider text-gray-100">AC3-Plus 3PAO Evidence Package</h2>
        <p className="text-gray-400 mt-2 text-sm max-w-3xl">
          Automated assembly of the complete 3PAO evidence package matching FedRAMP template structure. Generates ZIP with manifest, evidence artifacts, and control traceability matrix.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <FeatureCard title="Template-Matched Structure" />
            <FeatureCard title="Evidence Manifest" />
            <FeatureCard title="Control Traceability Matrix" />
            <FeatureCard title="Completeness Validation" />
            <FeatureCard title="ZIP Export" />
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <div className="flex items-center gap-3">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span className="text-sm text-gray-400">
            Connected to <code className="text-emerald-400">compliance.aceofcloud.io</code>
          </span>
        </div>
        <p className="text-xs text-gray-600 mt-2">
          This module communicates with the AC3-Plus Compliance API running on AWS ECS.
        </p>
      </div>
    </div>
  );
}

function FeatureCard({ title }: { title: string }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 hover:border-indigo-500/30 transition-colors">
      <div className="flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-indigo-400"></span>
        <span className="text-sm text-gray-300">{title}</span>
      </div>
    </div>
  );
}
