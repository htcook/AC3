# Ops Viewer DI Scan Debug - Round 4

## Key Finding
The visualization IS rendering! I can see nodes and edges in the bottom-right quadrant of the canvas.
The green/teal nodes are visible with connecting edges. The graph is rendering correctly.

However, the HUD still shows "0 NODES | 0 EDGES" - this is a display bug in the stats counter.

The visualization appears to be rendering in the bottom-right corner and may need a fitToView() call
or the stats counter needs to be updated when DI scan data is loaded.

## Issues:
1. HUD shows "0 NODES | 0 EDGES" even though nodes are visible - stats counter not updating
2. The graph may be partially off-screen - need fitToView to center it
3. The "LIVE" indicator shows correctly next to DEMO.TESTFIRE.NET

## Next Steps:
- Check why the HUD stats aren't updating - probably the engine stats aren't being read for DI mode
- The fitToView timeout (1500ms) may not be enough, or the stats update is tied to engagement mode only
