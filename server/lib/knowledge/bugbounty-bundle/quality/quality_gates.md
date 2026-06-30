# Quality & Safety Gates

## Required
- No credentials, API keys, tokens, cookies, session IDs
- No weaponized payload strings
- No direct step-by-step exploitation instructions beyond high-level safe tests
- Preserve "authorized scope" statement in training inputs

## Scoring (suggested)
- Completeness: 0-5
- Clarity: 0-5
- Safety: 0-5 (must be 5 to pass)
- Usefulness: 0-5

## Auto checks (regex ideas)
- key|token|secret|password|authorization:
- Bearer\s+[A-Za-z0-9\-\._]+
- session(id)?=