# Error Dashboard Findings (2026-03-27)

## Unresolved Errors by Category (19 distinct types, 316 total)

| # | Source | Severity | Message | Count | Latest |
|---|--------|----------|---------|-------|--------|
| 1 | unhandled_rejection | error | WebSocket closed without opened | 127 | 2026-03-20 |
| 2 | server | warning | Test error with engagement context | 58 | 2026-03-09 |
| 3 | react_boundary | critical | Spread syntax requires ...iterable[Symbol.iterator] to be a function | 43 | 2026-03-25 |
| 4 | react_boundary | critical | "undefined/app-auth" cannot be parsed as a URL | 16 | 2026-03-27 |
| 5 | react_boundary | critical | undefined is not an object (evaluating 'a.includes') | 13 | 2026-03-16 |
| 6 | react_boundary | critical | filteredNavGroups is not defined | 12 | 2026-03-16 |
| 7 | react_boundary | critical | Can't find variable: eng | 9 | 2026-03-11 |
| 8 | react_boundary | critical | Failed to fetch dynamically imported module: ReportsHub | 5 | 2026-03-17 |
| 9 | react_boundary | critical | Cannot access 'T' before initialization | 5 | 2026-03-26 |
| 10 | react_boundary | critical | Cannot read properties of undefined (reading 'toLocaleString') | 4 | 2026-03-15 |
| 11 | react_boundary | critical | Minified React error #310 | 4 | 2026-03-13 |
| 12 | react_boundary | critical | Failed to fetch dynamically imported module: Login | 3 | 2026-03-14 |
| 13 | react_boundary | critical | h.map is not a function | 3 | 2026-03-17 |
| 14 | react_boundary | critical | Failed to fetch dynamically imported module: SocIn | 3 | 2026-03-15 |
| 15 | react_boundary | critical | Failed to fetch dynamically imported module: Phish | 2 | 2026-03-16 |
| 16 | react_boundary | critical | Minified React error #31 | 2 | 2026-03-14 |
| 17 | react_boundary | critical | Rendered more hooks than during the previous render | 2 | 2026-03-25 |
| 18 | react_boundary | critical | 'text/html' is not a valid JavaScript MIME type | 2 | 2026-03-26 |
| 19 | react_boundary | critical | Can't find variable: X | 2 | 2026-03-26 |

## Triage

### Already Fixed (mark as resolved in DB)
- #4: "undefined/app-auth" URL parse — already fixed in previous session (stale import in TestPlanReview.tsx)
- #6: "filteredNavGroups is not defined" — likely fixed in sidebar refactor
- #7: "Can't find variable: eng" — likely fixed in engagement ops refactor

### Stale / Deployment Artifacts (mark as resolved)
- #1: "WebSocket closed without opened" — SSE fallback already implemented, WS errors are expected during transition
- #2: "Test error with engagement context" — test data, not real errors
- #8, #12, #13, #14, #15: "Failed to fetch dynamically imported module" — stale cache after deployment, users need hard refresh

### Need Code Fix
- #3: "Spread syntax requires ...iterable[Symbol.iterator]" — 43 occurrences, latest 2026-03-25, needs investigation
- #5: "undefined is not an object (evaluating 'a.includes')" — null safety issue
- #9: "Cannot access 'T' before initialization" — circular import or hoisting issue
- #10: "Cannot read properties of undefined (reading 'toLocaleString')" — null date/number
- #17: "Rendered more hooks than during the previous render" — conditional hook call
- #18: "'text/html' is not a valid JavaScript MIME type" — stale cache serving HTML instead of JS
- #19: "Can't find variable: X" — minified variable reference error
