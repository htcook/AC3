## Task
Generate safe, high-level Caldera planning hooks (no exploit details) based on signals.

Return YAML:
- suggested_objectives (e.g., validate auth hardening, validate patch level)
- suggested_abilities (high-level names only, like "Enumerate exposed endpoints", "Check TLS config")
- safety_notes (must include "No exploit payloads; authorized testing only")

Do NOT include commands, payloads, or step-by-step intrusion instructions.
