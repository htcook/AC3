# Risk Signal Analysis

## Signal Fields (all present and correct)
- signalId, assetId, signalType, severity, confidence, observedAt, rationale, evidenceRefs
- NO undefined fields in the actual signal data
- The "undefined" issue in the e2e test was likely from the test script formatting, not actual data

## Connector Status (vianova.ai scan)
Working connectors (7 with data): crtsh(102), shodan(102), wayback(502), urlscan(6), dehashed(2), email_security(4), cloud_assets(3), dns_deep(4), social-media(1)
Failed connectors (17 with errors): shodan_internetdb, censys, rdap, ripestat, securitytrails, binaryedge, greynoise, http_security, github_leaks, virustotal, hibp, whoisxml, leakix, fullhunt, netlas, hunter, abuseipdb, passivetotal

## Key Issues
1. 17 out of 27 connectors are failing - most due to missing API keys
2. Port data from Shodan has empty product/version - this is normal for Shodan's basic host info
3. Risk signals themselves are well-structured, no undefined fields
4. The "undefined" display issue needs to be checked in the DomainIntelResults.tsx rendering
