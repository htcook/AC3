# AC3 Bug Bounty Knowledge Training Pipeline

## Goal
Turn publicly disclosed bug bounty reports into structured reasoning data that trains an LLM to:
- infer vulnerability hypotheses from signals
- choose safe next tests
- explain impact clearly
- recommend fixes
- map to OWASP/CWE/MITRE (optional)

## Stages
1) Ingest (raw)
- Store source metadata + URL + retrieval timestamp + raw text

2) Normalize
- Extract: vuln class, entry point, auth model, steps, evidence, impact, remediation
- Remove secrets/tokens/PII
- Keep actions high-level (non-weaponized)

3) Patternize
- Convert normalized reports into reusable patterns (signals → hypothesis → safe tests → impact → fixes)

4) Generate Training Examples
- For each pattern, generate multiple "observation → reasoning" examples in JSONL

5) Quality & Safety Gates
- Ensure no payload strings
- Ensure no PII
- Ensure scope language present

6) Training / RAG
- Prefer RAG with the pattern library + ontology injection
- Fine-tune only after you have thousands of high-quality examples