# Ops Viewer DI Scan Debug - Round 5

## Key Findings
1. DI SCAN mode IS active (shows "DI SCAN | 8 FPS" in HUD)
2. DEMO.TESTFIRE.NET is selected in the dropdown
3. "LIVE" indicator shows next to the scan name
4. The canvas IS rendering nodes - I can see teal/green dots and connecting edges in the bottom-right area
5. BUT the HUD shows "0 NODES | 0 EDGES" - the stats counter is NOT updating

## Root Cause Analysis
The stats update fires when `this.frameCount === 0` which happens once per second after the FPS counter resets.
The simNodes array should have nodes since they're visually rendering on the canvas.

Wait - looking more carefully at the screenshot, the nodes ARE rendering but the stats say 0.
This means either:
a) The nodes are being drawn but not added to simNodes (unlikely since loadGraph sets simNodes)
b) The stats callback fires BEFORE loadGraph completes (timing issue)
c) The frameCount === 0 check is wrong - it should be checking right AFTER reset, not before

Actually looking at the code:
```
this.frameCount++; // increment
if (now - this.lastFpsTime > 1000) {
  this.currentFps = this.frameCount;
  this.frameCount = 0; // reset to 0
}
// ... draw ...
if (this.frameCount === 0) { // This fires when frameCount was just reset
```

Wait, this IS correct. frameCount gets set to 0, then the check fires. But it only fires once per second.
The issue might be that the stats callback fires but the React state doesn't update because the component re-renders.

Actually - I bet the issue is that `this.callbacks.onStatsUpdate` is stale because the callbacks useMemo has an empty dependency array.
No wait, the callback is `(s) => setStats(s)` which is a state setter - those are stable.

Let me check if the issue is that loadGraph is being called but the data has 0 nodes.
