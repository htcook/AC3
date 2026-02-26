## Task
Create 1 risk_card object per asset using schema/risk_card.schema.json.

Inputs:
- asset_id
- signals (for that asset)
- scoring guidance: scoring/hybrid-scoring.yaml
- optional: bia_score (0-10) and carver_score (0-10) if provided; otherwise derive conservative defaults from mappings.

Rules:
- final_score must be 0-10
- components.confidence_weight must be 0-1
- evidence should list observation_id and/or signal_id references
- recommendations must be defensive and actionable

Return JSON array of risk_card objects.
