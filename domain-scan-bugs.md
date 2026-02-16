# Domain Scan Bug Analysis

## Identified Issues

### 1. TabsList grid-cols mismatch (DomainIntelResults.tsx:336)
- `scan_complete` status shows `grid-cols-5` but has **6** TabsTrigger children
- This causes layout overflow but not a crash

### 2. Unsafe property access on scan data (DomainIntelResults.tsx)
- Line 208: `scan.campaignRecommendations` - could be null/undefined for scan_complete scans
- Line 209: `pipeline?.threatActorMatches` - safe with optional chaining
- Line 210: `pipeline?.llmThreatActorAnalysis` - safe with optional chaining

### 3. VulnIntelSection crash (DomainIntelResults.tsx:1929)
- `trpc.calderaProxy.matchTechVulns.useQuery({ scanId })` - this queries the `calderaProxy` router
- If the scan has no `pipelineOutput` or `pipelineOutput.assets` is undefined, the backend returns empty
- But if `matchTechnologiesAgainstAllFeeds` throws, the error handler shows a card - OK

### 4. Potential crash: `scan.pipelineOutput` as any (line 207)
- If `pipelineOutput` is stored as a JSON string instead of parsed object, accessing `.assets` etc. would fail
- Need to add safe JSON parse guard

### 5. Potential crash: `assets.flatMap` in findings tab (line 1213)
- `a.postureFindings` could be a JSON string instead of array
- Need to add safe parse guard

### 6. Potential crash: `scan.executiveSummary` passed to Streamdown (line 371)
- If executiveSummary is not a string (e.g., null), Streamdown might crash

### 7. Potential crash: `scan.threatModelSummary` passed to Streamdown (line 1141)
- Same issue as above

### 8. Most likely crash: DomainIntelResults data shape issues
- When `getScan` returns data, the `assets` array items may have properties stored as JSON strings
- `postureFindings`, `testVectors`, `technologies`, `tags`, `carverScores`, `shockScores` etc.
- If these are JSON strings instead of parsed objects, all the `.filter()`, `.map()`, `.length` calls would crash

### 9. TabsList grid-cols-5 has 6 children
- scan_complete: grid-cols-5 but 6 triggers (overview, assets, vulns, corroboration, findings, methods)
- Should be grid-cols-6
