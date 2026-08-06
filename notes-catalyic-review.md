# Catalyic.com PDF Review

## Page 1 — Cover
- Double footer issue STILL present: "AC3 Platform — Domain Intelligence Module" overlaps with "CONFIDENTIAL — For authorized recipients only" at bottom
- Large empty space between scan metadata and footer — could use more cover content
- Risk score 33 (LOW) with green box — looks good

## Page 2 — TOC
- Clean, 12 sections listed with page numbers
- Page-fill optimization working: sections 7 & 8 share page 13, sections 10 & 11 share page 15
- TOC looks professional

## Page 3 — Executive Summary
- BLUF paragraph is MUCH better — data-driven, concise, includes all key metrics
- BUT: "EXECUTIVE SUMMARY" header appears TWICE — once in the page header bar AND once in the rounded rect below it. Redundant.
- Key metrics dashboard table is clean and comprehensive
- Confidence statement is good
- Organization Profile table is clean
- Business Intelligence web crawl paragraph is informative
- Critical & High Risk Assets table at bottom — good page fill
- "mission_function" values show underscores: "public_facing_services", "business_continuity", "command_and_control" — should be human-readable

## Page 4 — Attack Surface Inventory
- Asset Distribution and Risk Distribution tables look clean
- Discovered Subdomains & Assets table is comprehensive — 21 assets, all shown
- Hosting column shows "—" for most (no hosting provider inferred) — only google.com shows "Google Cloud"
- Typosquat entries and phishtank entries included — good
- Some empty space at bottom but acceptable

## Page 5 — Domain Health & Blacklist Status
- Overall Domain Health box looks great — B (78) with category breakdown
- DNS Configuration, Email Security Posture, Blacklist/DNSBL tables all clean
- Phishing Difficulty: "VERY DIFFICULT to spoof" — GOOD, the wording fix is working!
- Blacklist table shows return codes, meanings, severity, action — all accurate
- TXT Record Evidence table shows raw DNS responses — good
- False Positive Analysis table started at bottom — page-fill working!

## Page 6 — Domain Health continued + Domain Registration (INLINE!)
- False Positive Analysis table continues from page 5
- DNS Security Configuration, Reverse DNS, Port Connectivity tables all clean
- PAGE-FILL WORKING: Domain Registration Details section starts INLINE on same page!
- Inline section header with rounded rect looks clean and professional
- Registration Risk Assessment shows [RISK] and [OK] items with evidence — looks great!
- Status codes correctly show all 4 locks present, and risk assessment correctly shows [OK] for transfer/delete locks

## Issues Found So Far:
1. P1: Double footer on cover page (still unfixed)
2. P1: "EXECUTIVE SUMMARY" label appears twice on page 3 (page header + rounded rect)
3. P2: Mission function values show underscores instead of spaces
4. P2: Hosting column shows "—" for most assets — hosting inference could be improved

## Page 7 — Registration Risk cont'd + Breach & Credential Exposure (INLINE!)
- Registration Risk Assessment flows from page 6 — [OK] items for Transfer/Delete lock look correct!
- PAGE-FILL WORKING: Breach & Credential Exposure starts INLINE with rounded header bar
- Credential Exposure Summary box looks clean — 227 leaked, 224 emails, 19 sources
- Breach Intelligence Summary 3-column layout is clean
- Breach Sources table lists all 19 sources
- Dark Web compact green note at bottom — "No dark web mentions detected" — perfect, no wasted page!

## Page 8 — Vulnerability & Technology Landscape
- Technology Stack table is comprehensive — 21 technologies, no duplicates visible!
- Confirmed Vulnerabilities (18) section starts with CVE cards
- CVE-2010-4345 (Exim) — Sev: Medium, CVSS: N/A, Ver: 4.98.2, KEV badge — looks accurate
- Each CVE card shows evidence line, affected assets list
- All 10 affected assets listed per CVE (all subdomains on same IP)

## Pages 9-12 — More CVE cards
- All CVE cards follow consistent format
- Mix of Exim (Medium) and OpenSSH (High) vulnerabilities
- Each shows Shodan detection details, version, affected assets
- CVSS shows N/A for all — this is because CVSS score isn't being pulled from NVD data
- All show "Public exploit available" in evidence line
- Affected assets list is identical for all (10 subdomains on same shared IP)

## Issues Found (continued):
5. P2: CVSS shows "N/A" for all CVEs — should pull from NVD data if available
6. P2: Affected assets list is very repetitive (same 10 assets for every CVE on same IP) — consider grouping by IP/service
7. P1: CVE section takes 5 pages (8-12) with repetitive affected asset lists — could be much more compact

## Page 13 — Last CVE + Provider-Managed Infrastructure (INLINE!) + Exploit Availability (INLINE!)
- PAGE-FILL WORKING: Provider-Managed Infrastructure flows inline after last CVE
- Provider section is clean — google.com excluded with explanation
- Exploit Availability & Default Credentials flows inline after Provider section
- BUT: Exploit table is ALL "Unknown" / "N/A" / Severity 5 / No — 180 rows of useless data!
- The exploit data has no source, module ID, or technology — completely uninformative

## Page 14 — More exploit unknowns + Compliance & Container Exposure (INLINE!)
- More rows of Unknown/N/A exploit data — waste of space
- Compliance section flows inline — PAGE-FILL WORKING
- Compliance Assessment table is clean — 33%, CIS + DISA STIG + NIST 800-53
- Failed Compliance Checks table is informative with check IDs, titles, severity, category, remediation

## Page 15 — More compliance + Cross-Module Intelligence (INLINE!) + Recommendations (INLINE!)
- Compliance table continues from page 14
- Cross-Module Intelligence section flows inline — but sparse (0 correlations, 0 findings, 0 adjustments)
- Bug Bounty: No program detected — good
- Prioritized Recommendations flows inline — 3 recommendations with priority, category, effort
- Identified Attack Chains section with 2 chains — good narrative content!
- Recommendations text is truncated with "..." — should show full text

## Page 16 — Appendix: Data Sources & Methodology
- Data Sources Queried table is comprehensive — all connectors listed with obs count, duration, status
- Many connectors show "Error: Skipped: No API key configured" — expected for unconfigured sources
- Some errors: crt.sh, commoncrawl, GitHub rate limit — operational issues

## Page 17 — Scan Metadata
- Clean metadata table with all scan details
- Confirmed Findings: 123 — matches cover page and BLUF!
- Total Findings: 390 — matches BLUF!
- Large empty space on page 17 — could add disclaimer or methodology notes

## FINAL ISSUE LIST:
1. P0: Exploit table is ALL "Unknown/N/A" — 180 rows of completely useless data. Must filter out entries with no source/module/technology.
2. P1: Double footer on cover page — overlapping CONFIDENTIAL lines
3. P1: "EXECUTIVE SUMMARY" label appears twice on page 3 (page header + BLUF box header)
4. P1: CVE section takes 5 pages with repetitive affected asset lists (same 10 assets per CVE) — needs compacting
5. P1: Recommendations text truncated with "..." — should show full text or at least more
6. P2: Mission function values show underscores (public_facing_services) — should be human-readable
7. P2: CVSS shows "N/A" for all CVEs
8. P2: Effort column shows "short_term" with underscore
