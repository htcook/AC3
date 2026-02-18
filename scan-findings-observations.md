# Findings Tab Observations

## Stats
- **0 CONFIRMED** (Version-matched CVEs)
- **837 PROBABLE** (Product-match, version unconfirmed)
- **71 POTENTIAL** (LLM-inferred, advisory only)

## Confirmed vs Potential Separation
- The findings tab correctly shows 3 categories with counts
- Currently viewing PROBABLE section (837 findings)
- Need to scroll down to verify POTENTIAL section has "NOT RATED" badges

## First Finding Displayed
- CVE-2023-44487: HTTP/2 Rapid Reset Attack (IETF HTTP/2)
- Tagged as PROBABLE with KEV badge
- Severity: 6/10 (capped), CVSS: 9, Likelihood: 6/10
- Shows "Version not detected — product-family match only (severity capped)"
- Full attribution chain shown: SOURCE, EVIDENCE, VERIFY, FP RISK

## No F5 BIG-IP
- No F5 BIG-IP findings visible — fix confirmed working!
