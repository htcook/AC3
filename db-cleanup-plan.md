# DB Cleanup Plan

## Current State
- Total scans: 484
- Empty scans (0 assets, 0 findings): 415
- Real scans with data: 69
- Failed scans: 0
- Test domain scans: 200
- Orphaned assets: 0

## Cleanup Strategy
1. Delete all scans where totalAssets=0 AND totalFindings=0 (415 rows)
2. Also delete test-domain scans that have synthetic data (e.g., enterprise-*.com, update-*.com, trpc-*.com, ack-test-*.com, test-*.com, changes-test-*.com, get-test-*.com, test-monitor-*.com)
3. Keep only real domain scans: vianova.ai, aceofcloud.com, zoom.us, and any future real scans
4. Delete associated discovered_assets for deleted scans
5. Clean up orphaned chain_stage_results
