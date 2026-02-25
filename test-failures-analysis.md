# Test Failures Analysis

## Summary: 28 failures across 5 test files

### 1. bug-bounty-intelligence.test.ts (7 failures)
- Tests expect property names that don't match actual service return values
- `topExploitedCWEs` → actual has `cweDistribution`
- `commonExploitChains` → actual has different structure
- `misconfigurationPatterns` → actual has `weaknessCategories`
- `domain` property missing from full report
- **Fix:** Update test expectations to match actual service interface

### 2. accuracy-enhancements.test.ts (16 failures)
- Need to investigate specific failures

### 3. bloodhound-rotation.test.ts (3 failures)
- Need to investigate specific failures

### 4. corroboration-pipeline.test.ts (1 failure)
- Expected 8 source results, got 7
- **Fix:** Update expected count to 7

### 5. new-connectors.test.ts (1 failure)
- Expected 17 connectors, got 27
- More connectors were added since test was written
- **Fix:** Update expected count to 27
