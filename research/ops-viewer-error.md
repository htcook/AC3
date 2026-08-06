# Ops Viewer DI Scan Error

Error: `TypeError: (s || "").toLowerCase is not a function`
Context: Occurs when selecting a DI scan (PBS.ORG) in the Ops Viewer

This means somewhere in the transform pipeline, a value that should be a string is actually an object or number, and `.toLowerCase()` is being called on it.

Likely culprits in battlespace-transform.ts:
- normalizeSeverity() calls toLowerCase on its input
- guessPlatform() or guessProtocolsFromTech() might receive non-string values
- detectProxy() calls tech.toLowerCase()
- detectInterception() might receive non-string values
