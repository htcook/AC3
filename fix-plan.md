# Fix Plan

## 1. CVE Ordering by Most Recent Date
- KNOWN_TECH_CVES already has `publishedDate` field on every CVE
- CveActorEnrichment interface needs a `publishedDate` field added
- enrichedCves.push() needs to include publishedDate from vuln.publishedDate
- Add "date" sort option to sortBy state and sort controls
- Default sort should be "date" (most recent first) instead of "priority"
- Sort: parse publishedDate and sort descending

## 2. Threat Actor Default Sorting
- Find where threat actors are listed/sorted in the UI
- Change default sort to most recently active (by lastExploited or lastActive date)
- Files: ThreatIntel page, DomainIntelResults threat actor sections

## 3. Passive Scan Disclaimer & Engagement CTA
- Add a banner component to DomainIntelResults.tsx
- Show after scan completes, before findings
- Explain passive-only nature
- CTA to create engagement + generate ROE
- Link to /engagements/new or similar

## 4. Sidebar Menu Reorganization
- See sidebar-audit.md for full analysis
