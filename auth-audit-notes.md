# Auth Audit Notes

## Finding: Published site redirects to login
When visiting https://calderadash-vmwwcxqy.manus.space/, the page shows the Login page, NOT the Home page.
This means the published version may have different routing than the dev server.

## Dev server check needed
Need to check if the dev server at localhost:3000 shows the Home page at / route.

## Routes identified as unprotected in App.tsx:
1. `/` → Home (public landing page)
2. `/overview` → Home (alias)
3. `/login` → Login (intentionally public)
4. `/portal/:token` → ClientPortal (token-based auth, intentional)
5. `/404` → NotFound (intentionally public)

## Links on Home page that go to protected routes:
1. Nav "COMMAND CENTER" → /dashboard
2. Hero "START TESTING YOUR DEFENSES" → /dashboard
3. CTA "ENTER COMMAND CENTER" → /dashboard
4. "VIEW FULL KSI DASHBOARD" → /ksi-dashboard
5. About section "ENTER COMMAND CENTER" → /dashboard

## Current protection:
- All destination routes (/dashboard, /ksi-dashboard) ARE wrapped in ProtectedRoute
- ProtectedRoute checks calderaAuth.session and redirects to /login if not authenticated
- So clicking those buttons from homepage WILL redirect to login

## Fix applied:
- Updated ProtectedRoute to include returnTo param when redirecting to login
- Updated Login page to support returnTo param for post-login redirect
