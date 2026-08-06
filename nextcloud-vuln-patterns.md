# Nextcloud Vulnerability Patterns (from 249 Security Advisories)

## Recent Advisory Types (Page 1 - Most Recent)
1. **RCE** — Remote code execution in Nextcloud Flow via vulnerable Windmill version (HIGH)
2. **Predictable tokens** — Calendar app used predictable proposal participant tokens (MODERATE)
3. **XSS** — XSS in SVG images when opened outside of Nextcloud (MODERATE)
4. **HTML injection** — Mail stored HTML injection in subject text (LOW)
5. **Authorization bypass** — Tables app share information not limited to relevant users (MODERATE)
6. **IDOR** — Contacts search allowed users to retrieve contact info of other users (MODERATE)
7. **Permission bypass** — Read-only users can restore deleted files from trash bin (LOW)
8. **Authorization bypass** — Approval app allows users to request approval for other users' files (LOW)
9. **Authentication bypass** — Calendar app allowed booking without generated token (LOW)
10. **Authorization bypass** — Users can modify tags on files that don't belong to them (MODERATE)

## Vulnerability Categories to Test
1. **XSS (Stored/Reflected)** — SVG uploads, file names, comments, sharing, calendar events, mail
2. **Authorization/Access Control (IDOR)** — Cross-user data access, share permissions, group folders
3. **Authentication Bypass** — Token prediction, session management, OAuth/OIDC flows
4. **Permission Escalation** — User → Admin, read-only → write, share permission violations
5. **Remote Code Execution** — File upload processing, server-side template injection, deserialization
6. **SQL Injection** — Search queries, API parameters, OCS endpoints
7. **Path Traversal** — File operations, WebDAV, external storage
8. **CSRF** — State-changing operations without proper token validation
9. **HTML Injection** — Mail subjects, notifications, sharing descriptions
10. **Information Disclosure** — User enumeration (accepted), but data leakage across users
11. **E2E Encryption Bypass** — Client-side encryption circumvention
12. **Brute Force Protection Bypass** — Rate limiting circumvention
13. **Token/Secret Predictability** — Sharing tokens, calendar tokens, API tokens
