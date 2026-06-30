# Nextcloud Threat Model & Accepted Risks

## Accepted Risks (NOT bounty-worthy unless noted)
1. **Administrator privileges** — Admins are ultimately trusted; expected they can execute arbitrary code
2. **Denial of Service** — PHP-based, DoS not fully preventable; not bounty-worthy
3. **Beta/PoC features** — Limited bounty, case-by-case
4. **Local external storage** — Considered trusted (symlinks followed with web server privileges)
5. **Server-side encryption** — Only bounty-worthy with external storage vector or per-user-keys data-at-rest
6. **Client-side (E2E) encryption** — Circumventing RFC security properties IS bounty-worthy
7. **Insecure features disabled by default** — Not bounty-worthy (e.g., LibreOffice preview provider)
8. **Version disclosure** — Accepted risk
9. **Content spoofing** — Not bounty-worthy
10. **ADB/XCode attacks** — Low/medium risk, may be excluded from monetary rewards
11. **User enumeration** — Not a security risk (expected for federation features)
12. **Brute force** — Nextcloud 12+ has brute force protection; bypasses may qualify
13. **SSRF** — Accepted behavior (federation features); deploy in segregated network
14. **App isolation** — Apps not isolated from each other; considered acceptable

## What IS Bounty-Worthy
- E2E encryption bypasses
- Authentication bypasses
- Authorization/access control violations (accessing other users' data)
- Remote code execution
- SQL injection
- XSS (stored, reflected)
- CSRF with security impact
- Path traversal / file access outside intended scope
- Brute force protection bypasses
- Privilege escalation (user → admin)

## Key Testing Notes
- Must test against current source code (not just demo instances)
- Files in test/vendor folders not packaged in releases — verify file exists in final release
- Only in-house nextcloud/ repos get monetary rewards (not third-party libraries)
- Collabora Online bugs → report to Collabora, not Nextcloud
- JIRA instance at nextcloud.atlassian.net is NOT theirs
