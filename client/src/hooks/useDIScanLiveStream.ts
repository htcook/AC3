/**
 * useDIScanLiveStream — Real-time progressive rendering for DI Scan mode in Ops Viewer
 * ═══════════════════════════════════════════════════════════════════════════
 * Subscribes to WebSocket events for an active DI scan and incrementally
 * adds nodes/edges to the BattlespaceEngine as discoveries happen in real-time.
 *
 * Event → Node/Edge mapping:
 * - di:scan_started       → scan status indicator
 * - di:stage_changed      → pipeline stage progress
 * - di:asset_discovered   → host/subdomain node + dns_resolve edge
 * - di:finding_detected   → vulnerability node + network_link edge
 * - di:interception_detected → tap_point/defense node + intercepts edge
 * - di:threat_matched     → threat_actor node + targets edges
 * - di:scan_complete      → final status update
 * - di:connector_progress → connector status overlay
 */
import { useEffect, useRef, useCallback } from "react";
import { useWebSocket, type WsEvent, type WsEventType } from "./useWebSocket";
import type {
  BattlespaceNode,
  BattlespaceEdge,
  SeverityLevel,
} from "@/lib/battlespace-types";

/** DI scan events that produce graph updates */
const DI_GRAPH_EVENT_TYPES: WsEventType[] = [
  "di:scan_started",
  "di:stage_changed",
  "di:asset_discovered",
  "di:finding_detected",
  "di:interception_detected",
  "di:threat_matched",
  "di:scan_complete",
  "di:connector_progress",
];

interface DIScanLiveStreamOptions {
  scanId: number | null;
  domain?: string;
  /** The engine's addNodes method — call to incrementally add nodes/edges */
  onNodesDiscovered?: (nodes: BattlespaceNode[], edges: BattlespaceEdge[]) => void;
  /** Called when scan stage changes */
  onStageChanged?: (stage: string, previousStage: string) => void;
  /** Called with live event count for status display */
  onEventCount?: (count: number) => void;
  /** Called when scan completes */
  onScanComplete?: (data: { totalAssets: number; totalFindings: number; overallRiskScore: number }) => void;
  /** Called when connector makes progress */
  onConnectorProgress?: (connector: string, status: string) => void;
  enabled?: boolean;
}

/** Deduplicate node IDs already added to the engine */
const addedNodeIds = new Set<string>();
const addedEdgeKeys = new Set<string>();

function edgeKey(src: string, tgt: string, type: string): string {
  return `${src}→${tgt}:${type}`;
}

function makeSeverity(sev?: string): SeverityLevel {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "info";
}

export function useDIScanLiveStream(options: DIScanLiveStreamOptions) {
  const {
    scanId,
    domain,
    onNodesDiscovered,
    onStageChanged,
    onEventCount,
    onScanComplete,
    onConnectorProgress,
    enabled = true,
  } = options;

  const eventCountRef = useRef(0);
  const currentStageRef = useRef<string>("");
  const rootNodeIdRef = useRef<string>("");

  // Reset dedup sets when scan changes
  useEffect(() => {
    addedNodeIds.clear();
    addedEdgeKeys.clear();
    eventCountRef.current = 0;
    currentStageRef.current = "";
    rootNodeIdRef.current = domain ? `domain-live-${domain}` : "";
  }, [scanId, domain]);

  // Subscribe to DI scan WS events
  const ws = useWebSocket({
    filterTypes: DI_GRAPH_EVENT_TYPES,
    enabled: enabled && !!scanId,
  });

  // Process incoming events
  const processEvent = useCallback(
    (event: WsEvent) => {
      if (!event?.data) return;

      // Filter by scanId
      const evtScanId = event.data.scanId;
      if (scanId && evtScanId && evtScanId !== scanId) return;

      eventCountRef.current++;
      onEventCount?.(eventCountRef.current);

      const nodes: BattlespaceNode[] = [];
      const edges: BattlespaceEdge[] = [];

      switch (event.type) {
        case "di:scan_started": {
          // Create root domain node if not already added
          const rootId = rootNodeIdRef.current || `domain-live-${event.data.domain}`;
          rootNodeIdRef.current = rootId;
          if (!addedNodeIds.has(rootId)) {
            addedNodeIds.add(rootId);
            nodes.push({
              id: rootId,
              type: "domain",
              label: event.data.domain,
              hostname: event.data.domain,
              severity: "info",
              priorityScore: 0.5,
              weaknessLevel: 0,
            });
          }
          break;
        }

        case "di:stage_changed": {
          const prev = currentStageRef.current;
          currentStageRef.current = event.data.stage;
          onStageChanged?.(event.data.stage, prev);
          break;
        }

        case "di:asset_discovered": {
          const asset = event.data.asset;
          if (!asset?.hostname) break;
          const assetId = `live-asset-${asset.hostname}`;

          if (!addedNodeIds.has(assetId)) {
            addedNodeIds.add(assetId);
            const techs = asset.technologies || [];
            nodes.push({
              id: assetId,
              type: asset.assetType === "subdomain" ? "subdomain" : "host",
              label: asset.hostname,
              hostname: asset.hostname,
              severity: makeSeverity(asset.riskBand),
              weaknessLevel: (asset.hybridRiskScore || 0) / 100,
              priorityScore: (asset.missionImpactScore || asset.hybridRiskScore || 0) / 100,
              technologies: techs,
            });

            // Connect to root domain
            const rootId = rootNodeIdRef.current;
            if (rootId) {
              const ek = edgeKey(rootId, assetId, "dns_resolve");
              if (!addedEdgeKeys.has(ek)) {
                addedEdgeKeys.add(ek);
                edges.push({
                  id: `dns-${rootId}-${assetId}`,
                  source: rootId,
                  target: assetId,
                  type: "dns_resolve",
                  weight: 0.5,
                  probability: 1,
                });
              }
            }
          }
          break;
        }

        case "di:finding_detected": {
          const { hostname, finding } = event.data;
          if (!hostname || !finding) break;

          const assetId = `live-asset-${hostname}`;
          const findingId = `live-finding-${hostname}-${(finding.title || "").replace(/\s+/g, "-").toLowerCase().slice(0, 40)}-${Date.now()}`;

          if (!addedNodeIds.has(findingId)) {
            addedNodeIds.add(findingId);
            nodes.push({
              id: findingId,
              type: "vulnerability",
              label: finding.title || "Finding",
              severity: makeSeverity(finding.severity),
              weaknessLevel: finding.severity === "critical" ? 0.95 : finding.severity === "high" ? 0.75 : 0.5,
              hostname,
            });

            if (addedNodeIds.has(assetId)) {
              const ek = edgeKey(assetId, findingId, "network_link");
              if (!addedEdgeKeys.has(ek)) {
                addedEdgeKeys.add(ek);
                edges.push({
                  id: `vuln-${assetId}-${findingId}`,
                  source: assetId,
                  target: findingId,
                  type: "network_link",
                  weight: 0.4,
                });
              }
            }
          }
          break;
        }

        case "di:interception_detected": {
          const { interception } = event.data;
          if (!interception) break;

          const tapId = `live-tap-${interception.vendor}-${interception.product}`.replace(/\s+/g, "-").toLowerCase();

          if (!addedNodeIds.has(tapId)) {
            addedNodeIds.add(tapId);
            nodes.push({
              id: tapId,
              type: "tap_point",
              label: `${interception.vendor} ${interception.product}`,
              hostname: event.data.domain,
              tapType: interception.category === "network" ? "ids_inline" : "ssl_inspection",
              interceptedBy: `${interception.vendor} ${interception.product}`,
              isIntercepted: true,
              severity: "high",
              priorityScore: interception.confidence,
            });

            // Connect interception to all known asset nodes
            for (const nodeId of addedNodeIds) {
              if (nodeId.startsWith("live-asset-")) {
                const ek = edgeKey(tapId, nodeId, "intercepts");
                if (!addedEdgeKeys.has(ek)) {
                  addedEdgeKeys.add(ek);
                  edges.push({
                    id: `intercept-${tapId}-${nodeId}`,
                    source: tapId,
                    target: nodeId,
                    type: "intercepts",
                    weight: 0.9,
                    probability: interception.confidence,
                    isIntercepted: true,
                    interceptedBy: `${interception.vendor} ${interception.product}`,
                    interceptionType: interception.domain === "network" ? "inline" : "logged",
                  });
                }
              }
            }
          }
          break;
        }

        case "di:threat_matched": {
          const { threatGroup } = event.data;
          if (!threatGroup) break;

          const groupId = `live-threat-${threatGroup.groupId}`;

          if (!addedNodeIds.has(groupId)) {
            addedNodeIds.add(groupId);
            nodes.push({
              id: groupId,
              type: "threat_actor",
              label: threatGroup.groupName,
              threatGroupId: threatGroup.groupId,
              threatLevel: threatGroup.riskLevel,
              severity: makeSeverity(threatGroup.riskLevel),
              priorityScore: threatGroup.matchScore / 100,
            });

            // Connect threat actor to all known asset nodes
            for (const nodeId of addedNodeIds) {
              if (nodeId.startsWith("live-asset-") && threatGroup.matchScore > 50) {
                const ek = edgeKey(groupId, nodeId, "targets");
                if (!addedEdgeKeys.has(ek)) {
                  addedEdgeKeys.add(ek);
                  edges.push({
                    id: `targets-${groupId}-${nodeId}`,
                    source: groupId,
                    target: nodeId,
                    type: "targets",
                    weight: threatGroup.matchScore / 100,
                    probability: threatGroup.matchScore / 100,
                  });
                }
              }
            }
          }
          break;
        }

        case "di:scan_complete": {
          onScanComplete?.({
            totalAssets: event.data.totalAssets,
            totalFindings: event.data.totalFindings,
            overallRiskScore: event.data.overallRiskScore,
          });
          break;
        }

        case "di:connector_progress": {
          onConnectorProgress?.(event.data.connector, event.data.status);
          break;
        }
      }

      // Push discovered nodes/edges to the engine
      if (nodes.length > 0 || edges.length > 0) {
        onNodesDiscovered?.(nodes, edges);
      }
    },
    [scanId, onNodesDiscovered, onStageChanged, onEventCount, onScanComplete, onConnectorProgress]
  );

  // Process new events as they arrive
  useEffect(() => {
    if (!ws.lastEvent) return;
    processEvent(ws.lastEvent);
  }, [ws.lastEvent, processEvent]);

  return {
    isConnected: ws.status === "connected",
    eventCount: eventCountRef.current,
    currentStage: currentStageRef.current,
  };
}
