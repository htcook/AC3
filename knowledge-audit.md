# Knowledge Module Audit — Training Data Ingestion Status

## Summary

| Module | Lines | Imported By (non-test) | LLM Injection Points | Status |
|--------|-------|----------------------|---------------------|--------|
| nmap-knowledge.ts | 806 | engagement-orchestrator, hunt-engine | Scan plan, vuln correlation, hunt | **WIRED** |
| owasp-knowledge.ts | 705 | engagement-orchestrator, scoring-engine, hunt-engine, owasp-coverage-tracker | Scan plan, vuln correlation, asset classification, hunt | **WIRED** |
| threat-group-knowledge.ts | 1116 | engagement-orchestrator, hunt-engine, threat-group router | Scan plan, vuln correlation, hunt, sector context | **WIRED** |
| bugbounty-knowledge.ts | 306 | engagement-orchestrator, hunt-engine | Scan plan, vuln correlation, exploitation | **WIRED** |
| cloud-security-knowledge.ts | 449 | engagement-orchestrator, scoring-engine, hunt-engine | Scan plan, vuln correlation | **WIRED** |
| attack-chain-retriever.ts | 176 | engagement-orchestrator, scoring-engine, hunt-engine | Vuln correlation, exploitation | **WIRED** |
| asset-ontology.ts | 232 | engagement-orchestrator, scoring-engine, hunt-engine | Scan plan, vuln correlation | **WIRED** |
| training-corpus.ts | 422 | engagement-orchestrator, hunt-engine | Scan plan, vuln correlation | **WIRED** |
| pentest-knowledge-base.ts | 1019 | error-log router ONLY | Role chat context only | **PARTIAL — NOT in main pipeline** |
| auth-testing-knowledge.ts | 1052 | auth-pipeline-engine, auth-assessment router | Auth testing pipeline only | **PARTIAL — NOT in main pipeline** |
| knowledge-store.ts | 521 | error-log router ONLY | RAG index for error log | **PARTIAL — NOT in main pipeline** |

## Gaps Found

1. **pentest-knowledge-base.ts** (1019 lines) — Contains 70+ technique entries, tool guides, and exploit dev knowledge. Only used in the error-log role chat, NOT injected into the main scan/vuln/exploit pipeline.

2. **auth-testing-knowledge.ts** (1052 lines) — Contains 6-phase auth testing methodology, 5 attack classes, CARVER overlay, SSO checks. Only used in the dedicated auth-assessment pipeline, NOT injected into the main engagement orchestrator's LLM prompts.

3. **knowledge-store.ts** (521 lines) — Contains RAG index with 9 source registries (OWASP, MITRE, HackTricks, PayloadsAllTheThings, etc.). Only used in error-log router, NOT used for main pipeline LLM context enrichment.

4. **functional-exploit-generator.ts** — Does NOT import any knowledge modules. The LLM generates exploits without the benefit of the pentest knowledge base, nmap knowledge, or OWASP knowledge.

5. **llm-post-enrichment-analysis.ts** — Does NOT import any knowledge modules. The LLM analyzes findings without knowledge context.

6. **LLM vuln synthesis prompt** (engagement-ops-core.ts:1632) — Does NOT inject any knowledge module context. Uses only inline prompt text with hardcoded test site hints.

## Recommendation

Wire the pentest-knowledge-base and auth-testing-knowledge into the main pipeline's LLM injection points:
- Vuln synthesis prompt should include OWASP + pentest technique context
- Exploit generator should include pentest-knowledge-base context
- Post-enrichment analysis should include threat-group and auth-testing context
