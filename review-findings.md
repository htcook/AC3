# Review Findings — Test Lab & Bug Bounty

## Issue Found: Test Lab NOT in Sidebar

The sidebar (AppShell.tsx) has `/training-lab` linked as "TRAINING LAB" but does NOT have any links to:
- `/test-lab` (TestLabDashboard)
- `/test-lab/environments` (TestLabEnvironments)
- `/test-lab/scenarios` (TestLabScenarios)
- `/test-lab/implant` (TestLabImplant)
- `/test-lab/training` (TestLabTraining)
- `/test-lab/graduation` (TestLabGraduation)

The Test Lab module has 6 routes and a full backend router but is NOT accessible from the sidebar navigation.

## Bug Bounty — OK
- `/bug-bounty` is in the sidebar as "BUG BOUNTY HUB" under the reconnaissance section
- Backend router `bugBountyRouter` is registered in routers.ts
- Full 1,445-line component with HackerOne sync, correlations, training, ScanForge bridge

## Action Required
Add Test Lab sub-navigation to the sidebar, either:
1. As a sub-section under an existing group (e.g., Ember/Agent section)
2. As its own section with sub-items for environments, scenarios, implant, training, graduation
