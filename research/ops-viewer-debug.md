# Ops Viewer Debug Notes

## Current State (2026-04-12)
- The Ops Viewer page loads correctly with the sidebar and canvas
- It shows "NO TARGET SELECTED - Select an engagement to visualize the attack surface"
- The mode tabs show: ENGAGEMENT | DI SCAN
- There's a "SELECT ENGAGEMENT" dropdown at the top
- The symbology legend is visible at the bottom left
- Stats show: 0 NODES | 0 EDGES | A 0.000 | ZOOM: MESO | 60%
- The canvas is empty because no engagement or DI scan is selected

## What the user likely means by "not seeing visualizations"
- Need to check: when a DI scan IS selected, does the visualization render?
- Need to switch to DI SCAN mode and select a scan to test
