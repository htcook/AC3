# Resume/Retry Bug Fix Notes

## Bug Summary
When scan crashes, operator hits "Retry Error" → restarts from passive scanning instead of current progress.

## Root Causes

### 1. "Retry" button calls `startPassiveScan` (WRONG)
- File: `client/src/pages/EngagementOps.tsx` line 2520
- The blue "Retry" button in the error banner calls `passiveScanMut.mutate()` 
- `passiveScanMut` = `trpc.engagementOps.startPassiveScan.useMutation()`
- `startPassiveScan` (server/routers/engagement-ops-core.ts:797) ALWAYS resets state.phase='recon' and starts fresh
- **FIX**: Replace with `resumeMut.mutate({ engagementId, resume: true, startPhase: resumeCapabilityQ.data?.nextPhase })`

### 2. `inferLastActivePhase` uses ANY log entry, not phase completion markers
- File: `server/routers/live-trigger-temp.ts` line 31
- Walks log backwards looking for any entry with a valid phase tag
- Should look for `type: 'phase_complete'` entries specifically to find COMPLETED phases
- **FIX**: Prioritize entries with type='phase_complete', fall back to any valid phase entry

### 3. `checkResumeCapability` advances to NEXT phase (skips incomplete work)
- File: `server/routers/live-trigger-temp.ts` line 206
- `nextPhase = PHASE_ORDER[lastPhaseIdx + 1]` — if crash during vuln_detection, suggests social_engineering
- **FIX**: When state.phase === 'error', resume from the SAME phase (the one that crashed), not the next one
- The `executeEngagement` already has `completedScans` tracking (nucleiCompleted, zapCompleted, etc.) that skips already-finished work within a phase

### 4. Same issue in `triggerExecution` procedure (line 70-100)
- Also advances to next phase: `execOptions.startPhase = PHASE_ORDER[lastPhaseIdx + 1]`
- **FIX**: When resuming from error, use the SAME phase

## Phase dispatch pattern in executeEngagement (line 4276+)
Each phase runs if startPhase is that phase OR any EARLIER phase:
- Phase 1 (recon): `if (startPhase === 'recon')`
- Phase 2 (passive_discovery): `if (['recon', 'passive_discovery'].includes(startPhase))`
- Phase 3 (scoping): `if (['recon', 'passive_discovery', 'scoping'].includes(startPhase))`
- Phase 5 (enumeration): `if (['recon', ..., 'enumeration'].includes(startPhase))`
- Phase 6 (vuln_detection): `if (['recon', ..., 'vuln_detection'].includes(startPhase))`

So if startPhase='vuln_detection', it will ONLY run vuln_detection and later phases (correct behavior).
If startPhase='passive_discovery', it will run passive_discovery AND all later phases (wrong for retry).

## Files to edit:
1. `server/routers/live-trigger-temp.ts` - Fix inferLastActivePhase + checkResumeCapability + triggerExecution
2. `client/src/pages/EngagementOps.tsx` - Fix "Retry" button to use resume instead of startPassiveScan
