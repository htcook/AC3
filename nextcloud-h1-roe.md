# Nextcloud HackerOne - Rules of Engagement

## Program Stats
- **Minimum bounty:** $100
- **Total bounties paid:** $127,618
- **Average bounty:** $150
- **Top bounty range:** $750 - $5,000
- **Reports received (90 days):** 928
- **Reports resolved:** 864
- **Assets in scope:** 94

## Reward Tiers
| Impact | Definition | Highest Reward |
|--------|-----------|---------------|
| Critical | Remote code execution on server as non-admin user (RCE) | $10,000 |
| High | Access to complete user data of any other user (Auth Bypass) | $4,000 |
| Medium | Limited disclosure of user data or single user session access (XSS with CSP bypass) | $1,500 |
| Low | Very limited disclosure or attacks requiring high user interaction | $500 |

## What They Want
- Bugs within Nextcloud server and apps supported by Nextcloud GmbH
- Only versions listed in Maintenance Schedule: https://github.com/nextcloud/server/wiki/Maintenance-and-Release-Schedule
- For Apps: only latest version compatible with eligible Server versions
- Bugs in mobile iOS and Android sync clients (latest store version only)
- Bugs in desktop clients for Mac, Windows, Linux (latest version only)
- **Must mention Nextcloud Server version or App version** or report closed as N/A
- Must be privilege escalation bugs ("Attacker can delete arbitrary files of other users" = good)
- Missing headers, info disclosure without impact = not rewarded
- DoS = acknowledged but NOT rewarded

## Rules / Restrictions
1. **Must reproduce yourself** with screenshots as proof
2. **No AI-generated reports** — Low-effort AI reports = Spam (-10 reputation) + possible suspension
3. If using LLMs, must disclose usage and manually verify all reproduction steps
4. **Do NOT leak report contents** to SaaS, AI services, search engines, browser plugins, translation engines
5. Only use locally-running LLM services
6. All reports must be **manually validated** — automated tool output alone not accepted
7. **No DoS attacks** against their infrastructure
8. **No automated testing tools** against their infrastructure
9. **Do not extract user data** from their infrastructure
10. **No disclosure** before patch is published
11. Reports must be short and concise
12. **Redact PII** in screenshots, server responses, JSON files
13. **Redact secrets, keys, credentials** in reports
14. **Third-party AppStore apps are NOT in scope**

## Key Implication for Our Engagement
- **MUST test on our own Nextcloud installation** — NOT against their infrastructure
- No automated scanning against nextcloud.com or any Nextcloud-operated servers
- All testing must be on self-hosted instance
- Must use supported/maintained versions only
- Must manually verify every finding before submission
- Source code review of GitHub repos IS allowed (94 repos in scope)
