# Google Project Zero Zero-Day Data Source Research

## Access URL (gviz CSV API - works with sheet name)
https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/gviz/tq?tqx=out:csv&sheet=All

## Columns (from header row)
1. CVE - CVE identifier (e.g. CVE-2026-5281)
2. Vendor - Vendor name (e.g. Google, Apple, Microsoft, Qualcomm)
3. Product - Product name (e.g. Chrome, iOS, Windows)
4. Type - Vulnerability type (e.g. Memory Corruption, Logic/Design Flaw)
5. Description - Brief description of the vulnerability
6. Date Discovered - Date the zero-day was discovered in the wild (may be "???")
7. Date Patched - Date the patch was released
8. Advisory - URL to vendor advisory
9. Analysis URL - URL to technical analysis (may be "???")
10. Root Cause Analysis - URL or reference to RCA (may be empty)
11. Reported By - Who reported/discovered the zero-day
12. (empty column)

## Data Stats
- 1063 zero-day entries (as of April 2026)
- Covers 2014 to present
- Updated regularly by Google TAG (moved from Project Zero)
- Separate year sheets available: 2014-2026

## Key Notes
- "???" means unknown/not yet available
- Data is public, no auth required
- gviz API supports per-sheet queries
