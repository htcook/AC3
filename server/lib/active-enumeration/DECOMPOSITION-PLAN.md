# Phase 5 (Active Enumeration) Decomposition Plan

## Source: `server/lib/engagement-phase-enumeration.ts` (2,087 lines)

## Major Sections Identified

| Section | Lines | Description | Sub-module |
|---------|-------|-------------|------------|
| RoE Scope Guard + DNS Pre-Resolution | 38-120 | Filter targets, resolve hostnames | `dns-resolver.ts` |
| Phase A Step 1: ScanForge Discovery | 121-405 | Port scanning, auto-retry, PCAP capture | `port-discovery.ts` |
| Phase A Step 2a: Service Fingerprinting | 407-595 | Protocol probes, CVE enrichment, diff | `service-fingerprinter-runner.ts` |
| Phase A Step 2a.1: Banner WAF Detection | 597-641 | WAF/IDS from TCP banners | (inline, small) |
| Phase A Step 2b: RDP/VoIP/Conferencing | 643-686 | Specialized service scanning | (inline, small) |
| Phase A Step 3: httpx HTTP Probing | 688-989 | HTTP probing, tech detection, port backfill | `httpx-prober.ts` |
| Phase A.5: Cloud Asset Detection | 1013-1128 | Cloud provider detection, storage scanning | `cloud-scanner-runner.ts` |
| Phase A.6: Context-Aware Profiling | 1130-1381 | WAF/CDN/topology, scan strategy | `target-profiler.ts` |
| Phase B: Targeted Tool Deployment | 1382-2087 | Tool selection, sanitization, parallel exec | `targeted-tool-runner.ts` |

## Extraction Strategy

Extract 5 major sub-modules (keeping small sections inline):

1. **`dns-resolver.ts`** (~80 lines) — DNS pre-resolution with training lab fallback
2. **`port-discovery.ts`** (~280 lines) — ScanForge discovery + auto-retry + PCAP hooks
3. **`httpx-prober.ts`** (~300 lines) — HTTP probing, tech/CDN detection, port backfill
4. **`cloud-scanner-runner.ts`** (~120 lines) — Cloud asset detection delegation
5. **`target-profiler.ts`** (~250 lines) — Context-aware profiling delegation
6. **`targeted-tool-runner.ts`** (~700 lines) — Phase B tool selection, sanitization, parallel execution

## Shared Context Interface

```typescript
interface EnumerationContext {
  state: EngagementOpsState;
  scopedAssets: Asset[];
  executeTool: (config: any) => Promise<ToolResult>;
  executeRawCommand: (cmd: string, timeout: number, opts: any) => Promise<ToolResult>;
  engagementAbortSignal: AbortSignal | undefined;
  helpers: {
    addLog: typeof addLog;
    broadcastOpsUpdate: typeof broadcastOpsUpdate;
    fmtTarget: typeof fmtTarget;
    genId: () => string;
    getEffectiveTarget: typeof getEffectiveTarget;
    isInRoeScope: typeof isInRoeScope;
    parseToolOutput: typeof parseToolOutput;
    persistScanResult: typeof persistScanResult;
    pushVulnDeduped: typeof pushVulnDeduped;
    broadcastReconFinding: typeof broadcastReconFinding;
    persistOpsStateDebounced: typeof persistOpsStateDebounced;
  };
}
```
