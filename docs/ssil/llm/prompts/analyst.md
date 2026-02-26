## Task
Given:
- scan_observations: [ ... ] (validated objects)
- signals: [ ... ] (validated objects)
Produce:
- Findings summary (bullets)
- Top risks (ranked, with confidence)
- Recommended next steps (defensive)
- Data gaps / follow-up passive checks

## Output format (YAML)
findings:
  - title:
    evidence:
    confidence:
    severity:
risks:
  - title:
    why_it_matters:
    confidence:
    severity:
next_steps:
  - action:
    reason:
data_gaps:
  - gap:
    suggested_passive_check:
