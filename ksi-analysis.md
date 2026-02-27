# KSI Coverage Analysis

## Two Data Sources with Discrepancy

### FedRAMPKSIMap.tsx (visual map component)
- Total KSIs: 45 (across 9 themes)
- Direct: 16 (36%)
- Supporting: 13 (29%)
- Planned: 16 (36%)
- Coverage (direct+supporting): 29 of 45 = **64%**

### ksi-evidence-chain.ts (evidence chain router)
- Total KSIs: 58 (across 11 themes including AFR, CMT, CNA)
- Direct: 31 (53%)
- Supporting: 20 (34%)
- Planned: 7 (12%)
- Coverage (direct+supporting): 51 of 58 = **88%**

## The Problem
1. FedRAMPKSIMap.tsx dynamically calculates COVERAGE_PCT from its own data = 64%
2. Home.tsx hardcodes "covers 87% of all 55 FedRAMP KSIs" at line 48
3. The evidence chain has 58 KSIs with 88% coverage (close to 87% claim)
4. But the visual map only has 45 KSIs with 64% coverage

## Root Cause
The two components track DIFFERENT KSI sets:
- FedRAMPKSIMap has 45 KSIs (fewer themes, more conservative)
- Evidence chain has 58 KSIs (more themes like AFR, more granular)
- The 87% claim in Home.tsx likely came from the evidence chain's 88%

## Fix Plan
1. The FedRAMPKSIMap dynamically calculates its own percentage — that's honest (currently 64%)
2. Home.tsx line 48 hardcodes "87%" — needs to be corrected to match the FedRAMPKSIMap's real number
3. Need to reconcile the two KSI sets or clarify which is authoritative
4. Best approach: use the FedRAMPKSIMap as authoritative (it's the user-facing visual) and update Home.tsx to match

## Files to Fix
- client/src/pages/Home.tsx line 48: "covers 87%" → use real calculated value
