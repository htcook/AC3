# LLM Prompt Pack: SSIL Scan Reasoning

Principles:
- Operate ONLY on normalized objects that validate against SSIL schemas.
- Never infer exploitability beyond available evidence.
- Prefer conservative wording; include confidence and the basis of each conclusion.
- Never provide instructions for wrongdoing. Focus on defensive remediation and risk explanation.

Files:
- system.md: System prompt baseline
- analyst.md: Analyst reasoning prompt
- risk_card.md: Produce explainable risk cards
- caldera_hooks.md: Produce safe emulation hooks (non-exploit, high-level)
- guardrails.md: Safety + compliance guardrails
