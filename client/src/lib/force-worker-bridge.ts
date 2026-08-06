/**
 * ForceWorkerBridge
 * ═══════════════════════════════════════════════════════════════════════
 * Thin wrapper around the d3-force WebWorker. Provides a clean API for
 * the BattlespaceEngine to offload simulation work.
 *
 * Falls back to main-thread d3-force if Workers are unavailable (e.g.
 * in test environments or very old browsers).
 */

export interface WorkerNodeInput {
  id: string;
  type: string;
  baseSize: number;
  clusterId?: string;
  x?: number;
  y?: number;
}

export interface WorkerEdgeInput {
  id: string;
  source: string;
  target: string;
}

export interface PositionUpdate {
  id: string;
  x: number;
  y: number;
}

export interface ForceWorkerCallbacks {
  onTick: (positions: PositionUpdate[], alpha: number) => void;
  onSettled: () => void;
}

export class ForceWorkerBridge {
  private worker: Worker | null = null;
  private callbacks: ForceWorkerCallbacks;
  private alive = true;

  constructor(callbacks: ForceWorkerCallbacks) {
    this.callbacks = callbacks;
    this.spawnWorker();
  }

  private spawnWorker(): void {
    try {
      // Vite handles the `?worker` import at build time, but we use
      // the standard `new Worker(new URL(...))` pattern for broader compat.
      this.worker = new Worker(
        new URL("./force-layout-worker.ts", import.meta.url),
        { type: "module" }
      );

      this.worker.onmessage = (e: MessageEvent) => {
        if (!this.alive) return;
        const msg = e.data;
        if (msg.type === "tick") {
          this.callbacks.onTick(msg.positions, msg.alpha);
        } else if (msg.type === "settled") {
          this.callbacks.onSettled();
        }
      };

      this.worker.onerror = (err) => {
        console.warn("[ForceWorkerBridge] Worker error, simulation will stop:", err.message);
      };
    } catch {
      console.warn("[ForceWorkerBridge] WebWorker unavailable — simulation will not run off-thread");
      this.worker = null;
    }
  }

  /** Whether the worker is alive and usable */
  get isAvailable(): boolean {
    return this.alive && this.worker !== null;
  }

  /** Initialize the simulation with a full node/edge set */
  init(nodes: WorkerNodeInput[], edges: WorkerEdgeInput[], config?: Record<string, number>): void {
    this.worker?.postMessage({ type: "init", nodes, edges, config });
  }

  /** Add nodes and edges incrementally */
  addNodes(nodes: WorkerNodeInput[], edges: WorkerEdgeInput[]): void {
    this.worker?.postMessage({ type: "addNodes", nodes, edges });
  }

  /** Reheat the simulation */
  reheat(alpha = 0.3): void {
    this.worker?.postMessage({ type: "reheat", alpha });
  }

  /** Pin a node (during drag) */
  pinNode(id: string, x: number, y: number): void {
    this.worker?.postMessage({ type: "pinNode", id, x, y });
  }

  /** Unpin a node (drag end) */
  unpinNode(id: string): void {
    this.worker?.postMessage({ type: "unpinNode", id });
  }

  /** Terminate the worker */
  destroy(): void {
    this.alive = false;
    this.worker?.postMessage({ type: "stop" });
    this.worker?.terminate();
    this.worker = null;
  }
}
