# Nikto Severity Misclassification Analysis

## Problem
"Uncommon header 'x-xss-protection'" is classified as HIGH severity.
This finding is duplicated 20+ times across engagements.

## Root Cause
The Nikto parser at line 2862-2877 in engagement-orchestrator.ts:
- "Uncommon header" does NOT match any of the severity rules:
  - No CVE → not "high" from CVE rule
  - No OSVDB → not "medium" from OSVDB rule  
  - Does NOT match "not present|not set|not defined|header.*missing" → not "low"
  - Does NOT match "directory indexing|listing|backup|config" → not "medium"
  - Does NOT match "injection|xss|rfi|lfi|traversal|upload" → not "high"
  - Does NOT match "default|sample|test|example" → not "low"
- Falls through to default severity = "info"

BUT WAIT — the actual DB shows severity = "high". This means the severity is being 
set ELSEWHERE, not in the Nikto parser. There must be a second severity assignment 
happening downstream.

## Two Issues
1. The "uncommon header" text contains "xss" in "x-xss-protection" which matches 
   the `/injection|xss|rfi|lfi|traversal|upload/i` pattern → classified as HIGH
2. Massive duplication — same finding appears 20+ times

## Fix Needed
1. Add "uncommon header" to the Nikto parser as "info" severity BEFORE the xss check
2. Dedup findings on insert in saveEngagementFindings()
