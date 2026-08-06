# PDF Report Review - aceofcloud.com (14 pages)

## Page 1 (Cover)
- ISSUE: "Confirmed Findings: 0" on cover but exec summary says "39 confirmed" — mismatch
- ISSUE: "Scan Duration: N/A" — should compute from connector durations
- ISSUE: Double footer — "CONFIDENTIAL" line appears twice at bottom, overlapping "AC3 Platform" text
- OK: Risk score 14/LOW, green badge, 26 assets, 5 data sources

## Page 2 (Table of Contents)
- ISSUE: TOC missing sections — no "Exploit Availability & Default Credentials" or "Cross-Module Intelligence & CARVER Profile" listed
- ISSUE: Section numbering jumps — goes 1-11 but the new sections (9, 10, 11) we added may not be in TOC
- NOTE: Section 9 shows "Compliance & Container Exposure" but our code has "Exploit Availability" as section 9
- OK: Clean layout, page numbers present

## Page 3 (Executive Summary)
- ISSUE: "35 CISA KEV Matches" — still showing 35 despite our tightened filter. The fix may not have been in the deployed version, OR the evidence flags (kevListed, kevMatch, kevData) are set on these observations
- ISSUE: "55 total finding(s)" but dashboard shows "39 confirmed, 1 probable, 15 potential" = 55 total — this is actually correct now!
- ISSUE: Large empty space below Organization Profile table — wasted half page
- OK: BLUF paragraph reads well, IP address shown for blacklist, findings breakdown populated
- OK: Key metrics dashboard table looks clean
- OK: Org profile table clean

## Page 4 (Attack Surface Inventory)
- ISSUE: "Total: 23 assets discovered" but cover says 26 and exec summary says 26 — mismatch (3 assets missing from table)
- ISSUE: outlook.com listed as an asset with risk score 46 MEDIUM — this is Microsoft's domain, not the client's. Should be excluded or flagged as third-party
- ISSUE: nsone.net listed as asset — this is NS1 DNS provider, not client-owned
- ISSUE: sender.zohoinvoice.com — third-party Zoho service, not client-owned
- OK: Risk distribution table clean, asset table formatting good

## Page 5 (Domain Health & Blacklist)
- ISSUE: DMARC shows "Policy: none" — this is a significant finding but not highlighted
- ISSUE: Phishing Difficulty says "DIFFICULT (HIGH RISK)" — confusing wording. Is it difficult to phish (good) or high risk of phishing (bad)?
- OK: Blacklist section looks great — return codes, meanings, severity, action required all present
- OK: False positive analysis table present
- OK: MXToolbox verification URL shown
- OK: DNS Security Configuration clean

## Page 6 (Reverse DNS & Port Connectivity)
- ISSUE: Huge empty space below Port Connectivity table — wasted 2/3 of page
- OK: PTR records and port connectivity data looks accurate

## Page 7 (Domain Registration Details)
- OK: Registration Risk Assessment looks great now! [RISK] and [OK] labels, colored borders, evidence citations all working
- OK: Transfer lock and delete lock correctly show as [OK] with green borders
- OK: DNSSEC and expiry correctly show as [RISK] with red borders
- OK: Summary line "2 risks, 0 warnings, 2 passed" accurate
- MINOR: Large empty space below assessment section

## Page 8 (Breach & Credential Exposure)
- ISSUE: Entire page is nearly empty — just a small dark card saying "Total Leaked Credentials: 0" and "No 1st-Party Breaches Detected"
- ISSUE: Wastes a full page for minimal content — should be combined with another section or condensed

## Page 9 (Dark Web & Ransomware Intelligence)
- ISSUE: Entire page is nearly empty — just a green banner saying "NO DARK WEB MENTIONS DETECTED"
- ISSUE: Another full wasted page — should be combined with breach section when both are empty

## Page 10 (Vulnerability & Technology Landscape)
- ISSUE: Section title says "Vulnerability & Technology Landscape" but only shows Technology Stack — no vulnerability data at all
- ISSUE: "Express" and "Express.js" listed as separate technologies — should be deduplicated
- ISSUE: "Node.js" and "Express" and "Express.js" are all the same ecosystem — noisy
- OK: Technology stack table formatting clean

## Page 11 (Provider-Managed Infrastructure)
- OK: Correctly identifies outlook.com and sender.zohoinvoice.com as managed by Microsoft 365
- OK: Explanation paragraph is clear about risk exclusion
- ISSUE: nsone.net is NOT listed here but it should be — it's NS1's DNS infrastructure, not client-owned
- ISSUE: Another mostly empty page

## Page 12 (Compliance & Container Exposure)
- OK: Compliance assessment table looks clean — 47% score, 7 passed, 8 failed
- OK: Failed checks table has good detail — check ID, title, severity, category, remediation
- ISSUE: Remediation text truncated with "..." — should show full text or wrap
- ISSUE: Category shows "http_security_hea..." truncated — should be "http_security_headers"
- ISSUE: No container exposure section visible despite section title including it

## Page 13 (Prioritized Recommendations)
- CRITICAL: Entire page is COMPLETELY BLANK — just the section header and nothing else
- This is the most important actionable section and it's empty

## Page 14 (Appendix: Data Sources & Methodology)
- ISSUE: "Confirmed Findings: 0" but exec summary says 39 confirmed — same mismatch as cover page
- ISSUE: "Duration: N/A" — should compute from connector durations
- ISSUE: Web Crawl shows "grade: F" but this isn't mentioned anywhere in the report body
- OK: Scan metadata table formatting clean

## PRIORITY FIX LIST

### P0 — Critical (data accuracy / empty sections)
1. Confirmed Findings mismatch: cover/appendix say 0, exec summary says 39 — the cover uses _confirmedVulnFindings (strict CVE filter) while BLUF uses observation corroboration. Need to align.
2. Prioritized Recommendations page is completely blank — the section renders nothing
3. KEV count still 35 — need to verify if evidence flags are actually set on these observations
4. "55 total findings" vs "39+1+15=55" — this is actually correct math, the breakdown works

### P1 — Important (wasted space / layout)
5. Empty pages: Breach (p8), Dark Web (p9), Recommendations (p13) are nearly/fully blank — combine empty sections or skip page breaks when no data
6. Large empty spaces on pages 3, 6, 7, 11 — avoid forcing new pages when content is small

### P2 — Moderate (content quality)
7. Compliance table text truncation — category and remediation columns cut off
8. Cover page double footer — overlapping CONFIDENTIAL lines
9. Phishing Difficulty wording confusing — "DIFFICULT (HIGH RISK)" is contradictory
10. Technology deduplication — Express vs Express.js
