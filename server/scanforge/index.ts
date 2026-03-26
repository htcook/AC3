/**
 * ScanForge — AC3 Vulnerability Scanner & DAST Engine
 *
 * A unified scanning service that replaces per-tool SSH invocation with:
 *   - Priority-based job queue with concurrent execution
 *   - RESTful API for scan lifecycle management
 *   - YAML template engine for extensible detection logic
 *   - Protocol-native scanners for 14+ protocols
 *   - Proactive TI/DFIR enrichment for scan planning and risk scoring
 *   - WebSocket events for real-time scan progress
 *
 * Usage:
 *   import { scanforgeRouter, initializeScanForge } from "./scanforge";
 *   await initializeScanForge();
 *   app.use("/api/v1", scanforgeRouter);
 */

export { scanforgeRouter, initializeScanForge } from "./api/router";
export { getScanQueue, ScanQueue } from "./queue/scan-queue";
export { getTemplateEngine, TemplateEngine } from "./engine/template-engine";
export { ScanOrchestrator } from "./engine/scan-orchestrator";
export { getProtocolRegistry, ProtocolRegistry } from "./protocols/registry";
export { getIntelligenceEngine, IntelligenceEngine } from "./intelligence/ti-engine";
export { getContextEngine, ContextEngine } from "./intelligence/context-engine";
export { getFPFNEngine, FPFNPreventionEngine } from "./intelligence/fp-fn-prevention";
export type * from "./types";
