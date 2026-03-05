# Domain Intelligence Discovery vs Engagement Passive Scan — Gap Analysis

## Summary

The **engagement passive scan** uses `strict_passive` mode which only allows **9 connectors** out of **32 total**. This means **23 connectors are blocked** during engagement passive recon, including many that are genuinely passive (query third-party APIs only, never touch the target).

## Connector Classification

### Currently Allowed in Strict Passive (9 connectors)

| Connector | Category | Touches Target? | Notes |
|-----------|----------|-----------------|-------|
| crtsh | certificates | No | Certificate Transparency logs |
| shodan | infrastructure | No | Pre-scanned database |
| shodan_internetdb | infrastructure | No | Free fast-path CVE/port lookup |
| censys | infrastructure | No | Pre-scanned database |
| wayback | historical | No | Wayback Machine archive |
| urlscan | web | No | Community scan database |
| securitytrails | dns | No | DNS intelligence API |
| dehashed | breaches | No | Breach database |
| binaryedge | infrastructure | No | **DEAD — API shut down March 2025** |

### Blocked But Should Be Allowed (Genuinely Passive — 14 connectors)

These query third-party APIs only and NEVER contact the target:

| Connector | Category | Why It's Safe | Impact of Gap |
|-----------|----------|---------------|---------------|
| coalition_control | infrastructure | Queries Coalition's pre-scanned DB | **Replaces dead BinaryEdge** — currently blocked! |
| virustotal | threat-intel | Queries VT's database | Missing malware/reputation data |
| hibp | breaches | Queries HIBP's database | Missing breach exposure data |
| whoisxml | whois | Queries WhoisXML API (not target WHOIS) | Missing WHOIS records + subdomain enum |
| leakix | leaks | Queries LeakIX's pre-scanned DB | Missing exposed service/leak data |
| fullhunt | infrastructure | Queries FullHunt's pre-scanned DB | Missing attack surface data |
| netlas | infrastructure | Queries Netlas's pre-scanned DB | Missing host scanning data |
| hunter | email | Queries Hunter.io's database | Missing email discovery data |
| social-media | social | Queries GitHub API | Missing social/code exposure data |
| abuseipdb | threat-intel | Queries AbuseIPDB's database | Missing IP reputation data |
| passivetotal | dns | Queries RiskIQ's database | Missing passive DNS/SSL history |
| github_leaks | code | Queries GitHub search API | Missing code leak/secret data |
| github_recon | code | Queries GitHub API | Missing org/repo/CI-CD exposure data |
| cloud_assets | cloud | Queries cloud provider APIs (not target) | Missing S3/Azure/GCP bucket data |

### Correctly Blocked in Strict Passive (9 connectors)

These touch the target infrastructure directly:

| Connector | Category | Why It's Blocked | Correct Classification |
|-----------|----------|------------------|----------------------|
| email_security | email | DNS resolution (SPF/DKIM/DMARC) | DNS_RESOLUTION — move to standard |
| dns_deep | dns | DNS resolution (all record types) | DNS_RESOLUTION — move to standard |
| http_security | web | Direct HTTPS to target (headers/WAF) | ACTIVE_CONTACT — move to standard |
| container-discovery | infrastructure | Direct HTTP to target ports | ACTIVE_CONTACT — move to active |
| cloud_bucket_recon | cloud | Direct HTTP to cloud providers (probes buckets) | ACTIVE_CONTACT — move to standard |
| rdap | whois | Queries RDAP servers | REGISTRATION — keep in standard |
| ripestat | infrastructure | DNS resolution before query | DNS_RESOLUTION — keep in standard |
| greynoise | threat-intel | DNS resolution before query | DNS_RESOLUTION — keep in standard |

## Recommended Fix

Update `STRICT_PASSIVE_CONNECTORS` in `passive-guard.ts` to include all 23 genuinely passive connectors:

```
STRICT_PASSIVE_CONNECTORS = {
  // Original (keep)
  crtsh, shodan, shodan_internetdb, censys, wayback, urlscan, securitytrails, dehashed,
  // Replace dead BinaryEdge
  coalition_control,
  // Third-party API only (add)
  virustotal, hibp, whoisxml, leakix, fullhunt, netlas, hunter,
  social-media, abuseipdb, passivetotal, github_leaks, github_recon, cloud_assets
}
```

Also update `DNS_RESOLUTION_CONNECTORS` to include `email_security` and `dns_deep`.

## Impact

After this fix, engagement passive scans will run **23 connectors** instead of 9, providing:
- 2.5x more data sources
- Cloud asset enumeration
- Code leak detection
- Breach exposure from multiple sources
- Full attack surface coverage from pre-scanned databases
- Threat intelligence from VT, AbuseIPDB, GreyNoise (via standard mode)
