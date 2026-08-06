# Attack Planner Specialist Fix Analysis

## Root Cause
The `planAttack` function in `server/lib/llm-specialists/attack-planner.ts` assembles a prompt that's too large:

1. **System prompt** = CORE_POLICY (~1K chars) + ROLE_PROMPT (~1.2K) + buildAssetContext (assets listed AGAIN) + bankingAttackCtx (full banking domain knowledge ~8-12K) + missedVulnCtx (missed vuln patterns)
2. **User message** = passiveReconSummary which is ALREADY `tier1Content + enrichmentCtx` (tier1Content has all assets + enrichmentCtx is capped at 12K chars)

So assets are listed THREE times:
- Once in buildAssetContext (system prompt)
- Once in tier1Content (user message via passiveReconSummary)
- Once in enrichmentCtx (user message via passiveReconSummary)

Plus banking context is injected TWICE:
- Once in enrichmentCtx (from the orchestrator's context blocks)
- Once in bankingAttackCtx (from the specialist's own injection)

## Fix Plan
1. **Cap the specialist's total prompt size** using capLLMContext
2. **Remove duplicate asset context** — since passiveReconSummary already contains asset data, don't also inject it via buildAssetContext
3. **Use compact banking context** (getBankingContextCompact) instead of full buildBankingDomainContext
4. **Truncate passiveReconSummary** if it exceeds budget after system prompt
5. **Add token estimation** and log a warning when prompt is large
6. **Improve the fallback** — the direct LLM fallback also uses tier1Content which may be large; use a trimmed version
