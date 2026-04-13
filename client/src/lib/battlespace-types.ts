/**
 * Ops Viewer — Shared Types & Visual Encoding Constants
 * ═══════════════════════════════════════════════════════════════════
 * MIL-STD-2525D inspired symbology with brutalist design system.
 * Dual-mode: Engagement Ops Viewer + DI Customer Demo
 */

// ── Node Types ──────────────────────────────────────────────────────
export type BattlespaceNodeType =
  | "host"           // Discovered host/server
  | "subnet"         // Network segment
  | "domain"         // DNS domain
  | "subdomain"      // Discovered subdomain
  | "service"        // Exposed service (port)
  | "vulnerability"  // Discovered weakness
  | "hypothesis"     // Inferred/hypothesized weakness
  | "credential"     // Discovered credential
  | "agent"          // Deployed C2 agent
  | "defense"        // WAF, FW, EDR, IDS
  | "threat_actor"   // Matched threat group
  | "ioc"            // Indicator of compromise
  | "data_asset"     // Exposed data (DB, file share, API)
  | "cloud_resource" // Cloud IAM, S3, Lambda
  | "pivot_point"    // Lateral movement node
  | "crown_jewel"    // High-value target
  | "proxy"          // Reverse proxy, CDN, load balancer (nginx, HAProxy, Cloudflare)
  | "gateway"        // Network hop, router, NAT gateway between platform and target
  | "c2_server"      // Our C2 infrastructure (Caldera, Sliver listener)
  | "tap_point";     // SOC/Blue team interception point (SPAN, SSL inspection, IDS inline)

export type BattlespaceEdgeType =
  | "network_link"   // L3/L4 connectivity
  | "exploits"       // Vulnerability exploitation
  | "enables"        // Access grant chain
  | "pivots_to"      // Lateral movement
  | "chains_with"    // Attack chain link
  | "protects"       // Defense → asset
  | "targets"        // Threat actor → asset
  | "indicates"      // IOC → threat
  | "data_flow"      // Data exfil path
  | "dns_resolve"    // Domain → IP
  | "trust"          // Trust relationship
  | "escalates"      // Privilege escalation
  | "proxies_to"     // Proxy/CDN/LB → target asset
  | "c2_channel"     // Agent → C2 server callback
  | "intercepts"     // Tap/SPAN/mirror point intercepting traffic
  | "routes_through" // Traffic routing through intermediate hop
  | "bypass";         // Direct path bypassing proxy/CDN (origin IP exposed)

export type ProtocolType = "tcp" | "udp" | "icmp" | "http" | "https" | "dns" | "smb" | "ssh" | "rdp" | "other";
export type PlatformType = "cloud" | "on_prem" | "hybrid" | "container" | "serverless" | "iot" | "unknown";
export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";
export type KillChainPhase = "recon" | "weaponize" | "deliver" | "exploit" | "install" | "c2" | "actions";

// ── Node Data ───────────────────────────────────────────────────────
export interface BattlespaceNode {
  id: string;
  type: BattlespaceNodeType;
  label: string;
  // Position (set by D3-force, can be overridden)
  x?: number;
  y?: number;
  fx?: number | null; // Fixed position
  fy?: number | null;
  // Visual encoding data
  severity?: SeverityLevel;
  weaknessLevel?: number;       // 0-1, maps to border thickness + color
  priorityScore?: number;       // 0-1, maps to size + glow intensity
  platform?: PlatformType;
  technologies?: string[];      // Tech stack badges
  protocols?: ProtocolType[];   // Protocol badges
  // Defense-specific
  defenseType?: string;         // waf | firewall | edr | ids | siem
  ruleCount?: number;           // Number of active rules
  // Threat intel
  threatGroupId?: string;
  threatLevel?: string;
  killChainPhase?: KillChainPhase;
  mitreIds?: string[];
  // Service-specific
  port?: number;
  serviceName?: string;
  version?: string;
  // Asset metadata
  hostname?: string;
  ip?: string;
  os?: string;
  // Cluster grouping
  clusterId?: string;           // Subnet or domain group
  // Defense details
  defenses?: string[];           // Active defense names on this node
  layer?: string;                // Network layer (application, transport, etc.)
  // State
  isHighlighted?: boolean;
  isSelected?: boolean;
  isNew?: boolean;              // Recently discovered (animate in)
  discoveredAt?: number;        // Timestamp
  // Proxy/Gateway metadata
  proxyVendor?: string;         // nginx, HAProxy, Cloudflare, Akamai, AWS ALB
  proxyRole?: "reverse_proxy" | "cdn" | "load_balancer" | "waf_inline" | "ssl_terminator";
  // C2 metadata
  c2Platform?: string;          // caldera, sliver, cobalt_strike
  c2Protocol?: string;          // http, https, dns, smb
  // Tap/Interception metadata
  tapType?: "span_port" | "ssl_inspection" | "ids_inline" | "traffic_mirror" | "proxy_intercept";
  interceptedBy?: string;       // SOC tool name or blue team indicator
  isIntercepted?: boolean;      // True if traffic through this node is being monitored
}

// ── Edge Data ───────────────────────────────────────────────────────
export interface BattlespaceEdge {
  id: string;
  source: string;
  target: string;
  type: BattlespaceEdgeType;
  protocol?: ProtocolType;
  // Visual encoding
  weight?: number;              // 0-1, maps to line thickness
  probability?: number;         // 0-1, maps to opacity
  dataFlow?: string;            // What flows along this edge
  // State
  isHighlighted?: boolean;
  isActive?: boolean;           // Currently being traversed
  killChainPhase?: KillChainPhase;
  // Interception indicators
  isIntercepted?: boolean;      // True if blue team is monitoring this link
  interceptionType?: "mirrored" | "inline" | "ssl_decrypted" | "logged";
  interceptedBy?: string;       // SOC tool or blue team indicator
  // Proxy bypass detection
  isBypassOpportunity?: boolean; // True if this edge represents a direct path that bypasses a proxy
  bypassesProxy?: string;        // ID of the proxy node being bypassed
}

// ── Visual Constants (Brutalist Design System) ──────────────────────

/** MIL-STD-2525D inspired color coding */
export const SEVERITY_COLORS = {
  critical: "#FF0040",  // Bright red
  high:     "#FF6B00",  // Orange
  medium:   "#FFB800",  // Amber
  low:      "#00E5CC",  // Teal (site accent)
  info:     "#4A5568",  // Muted gray
} as const;

/** Kill chain phase colors (progression from cool to hot) */
export const KILL_CHAIN_COLORS = {
  recon:     "#00E5CC",  // Teal
  weaponize: "#00B4D8",  // Cyan
  deliver:   "#FFB800",  // Amber
  exploit:   "#FF6B00",  // Orange
  install:   "#FF0040",  // Red
  c2:        "#D00070",  // Magenta
  actions:   "#8B0000",  // Dark red
} as const;

/** Node type visual config */
export const NODE_VISUAL_CONFIG: Record<BattlespaceNodeType, {
  shape: "rect" | "diamond" | "hexagon" | "circle" | "octagon" | "triangle";
  baseColor: string;
  strokeColor: string;
  icon: string;
  baseSize: number;
  zIndex: number;
}> = {
  host:           { shape: "rect",     baseColor: "#1A2332", strokeColor: "#2D4A6F", icon: "⬡", baseSize: 28, zIndex: 10 },
  subnet:         { shape: "hexagon",  baseColor: "#0D1B2A", strokeColor: "#1B3A5C", icon: "⎔", baseSize: 40, zIndex: 5 },
  domain:         { shape: "diamond",  baseColor: "#1A2332", strokeColor: "#00E5CC", icon: "◆", baseSize: 32, zIndex: 8 },
  subdomain:      { shape: "rect",     baseColor: "#141E2B", strokeColor: "#2D4A6F", icon: "◇", baseSize: 20, zIndex: 7 },
  service:        { shape: "circle",   baseColor: "#1A2332", strokeColor: "#3B82F6", icon: "●", baseSize: 18, zIndex: 9 },
  vulnerability:  { shape: "diamond",  baseColor: "#2A1215", strokeColor: "#FF0040", icon: "⚠", baseSize: 24, zIndex: 15 },
  hypothesis:     { shape: "diamond",  baseColor: "#1A1A2E", strokeColor: "#8B5CF6", icon: "?", baseSize: 22, zIndex: 14 },
  credential:     { shape: "octagon",  baseColor: "#2A1F00", strokeColor: "#FFB800", icon: "🔑", baseSize: 20, zIndex: 12 },
  agent:          { shape: "triangle", baseColor: "#001A0D", strokeColor: "#00FF88", icon: "▲", baseSize: 22, zIndex: 20 },
  defense:        { shape: "hexagon",  baseColor: "#0A1628", strokeColor: "#3B82F6", icon: "🛡", baseSize: 26, zIndex: 11 },
  threat_actor:   { shape: "octagon",  baseColor: "#2A0A0A", strokeColor: "#FF0040", icon: "☠", baseSize: 30, zIndex: 18 },
  ioc:            { shape: "circle",   baseColor: "#1A0A20", strokeColor: "#D946EF", icon: "◉", baseSize: 16, zIndex: 13 },
  data_asset:     { shape: "rect",     baseColor: "#0A1A28", strokeColor: "#06B6D4", icon: "⛁", baseSize: 22, zIndex: 9 },
  cloud_resource: { shape: "hexagon",  baseColor: "#0A1628", strokeColor: "#818CF8", icon: "☁", baseSize: 24, zIndex: 10 },
  pivot_point:    { shape: "diamond",  baseColor: "#1A1500", strokeColor: "#F59E0B", icon: "⤳", baseSize: 20, zIndex: 16 },
  crown_jewel:    { shape: "octagon",  baseColor: "#1A0A00", strokeColor: "#FFD700", icon: "★", baseSize: 34, zIndex: 25 },
  proxy:          { shape: "hexagon",  baseColor: "#0A2818", strokeColor: "#009639", icon: "⇋", baseSize: 26, zIndex: 12 },
  gateway:        { shape: "diamond",  baseColor: "#1A1A28", strokeColor: "#6B7280", icon: "⊳", baseSize: 20, zIndex: 8 },
  c2_server:      { shape: "triangle", baseColor: "#0A1A0A", strokeColor: "#00FF88", icon: "⌘", baseSize: 28, zIndex: 22 },
  tap_point:      { shape: "octagon",  baseColor: "#1A0A2A", strokeColor: "#FF4444", icon: "◎", baseSize: 24, zIndex: 23 },
};

/** Edge type visual config */
export const EDGE_VISUAL_CONFIG: Record<BattlespaceEdgeType, {
  color: string;
  dashPattern: number[];  // [] = solid
  particleColor: string;
  particleSpeed: number;
  width: number;
}> = {
  network_link: { color: "#1E3A5C", dashPattern: [],       particleColor: "#2D4A6F", particleSpeed: 1.0, width: 1 },
  exploits:     { color: "#FF0040", dashPattern: [],       particleColor: "#FF4060", particleSpeed: 2.5, width: 2 },
  enables:      { color: "#FF6B00", dashPattern: [8, 4],   particleColor: "#FF8C40", particleSpeed: 1.5, width: 1.5 },
  pivots_to:    { color: "#F59E0B", dashPattern: [12, 4],  particleColor: "#FFC040", particleSpeed: 2.0, width: 2 },
  chains_with:  { color: "#8B5CF6", dashPattern: [4, 4],   particleColor: "#A78BFA", particleSpeed: 1.8, width: 1.5 },
  protects:     { color: "#3B82F6", dashPattern: [2, 6],   particleColor: "#60A5FA", particleSpeed: 0.8, width: 1.5 },
  targets:      { color: "#FF0040", dashPattern: [16, 4],  particleColor: "#FF4060", particleSpeed: 3.0, width: 2.5 },
  indicates:    { color: "#D946EF", dashPattern: [4, 8],   particleColor: "#E879F9", particleSpeed: 1.2, width: 1 },
  data_flow:    { color: "#06B6D4", dashPattern: [6, 3],   particleColor: "#22D3EE", particleSpeed: 1.5, width: 1.5 },
  dns_resolve:  { color: "#00E5CC", dashPattern: [2, 2],   particleColor: "#00FFE0", particleSpeed: 0.5, width: 0.5 },
  trust:        { color: "#10B981", dashPattern: [10, 5],  particleColor: "#34D399", particleSpeed: 0.6, width: 1 },
  escalates:    { color: "#FF0040", dashPattern: [3, 3],   particleColor: "#FF4060", particleSpeed: 2.2, width: 2 },
  proxies_to:    { color: "#009639", dashPattern: [8, 2],   particleColor: "#00C853", particleSpeed: 1.2, width: 2 },
  c2_channel:    { color: "#00FF88", dashPattern: [12, 4, 2, 4], particleColor: "#00FF88", particleSpeed: 3.5, width: 2.5 },
  intercepts:    { color: "#FF4444", dashPattern: [2, 2, 8, 2], particleColor: "#FF6666", particleSpeed: 0.5, width: 3 },
  routes_through:{ color: "#6B7280", dashPattern: [6, 6],   particleColor: "#9CA3AF", particleSpeed: 1.0, width: 1 },
  bypass:         { color: "#FFD600", dashPattern: [4, 2, 4, 2], particleColor: "#FFE082", particleSpeed: 3.0, width: 2.5 },
};

/** Protocol line style encoding */
export const PROTOCOL_LINE_STYLE: Record<ProtocolType, { dashPattern: number[]; color: string }> = {
  tcp:   { dashPattern: [],          color: "#2D4A6F" },  // Solid
  udp:   { dashPattern: [6, 4],     color: "#4A6FA5" },  // Dashed
  icmp:  { dashPattern: [2, 2],     color: "#6B7280" },  // Dotted
  http:  { dashPattern: [12, 4, 2, 4], color: "#00E5CC" }, // Dash-dot
  https: { dashPattern: [12, 4, 2, 4], color: "#10B981" }, // Dash-dot (green)
  dns:   { dashPattern: [4, 8],     color: "#818CF8" },  // Short dash
  smb:   { dashPattern: [8, 2],     color: "#F59E0B" },  // Long dash
  ssh:   { dashPattern: [],          color: "#10B981" },  // Solid green
  rdp:   { dashPattern: [10, 5],    color: "#3B82F6" },  // Medium dash
  other: { dashPattern: [4, 4],     color: "#4A5568" },  // Regular dash
};

/** Platform type icon mapping */
export const PLATFORM_ICONS: Record<PlatformType, string> = {
  cloud:      "☁",
  on_prem:    "⬡",
  hybrid:     "⬢",
  container:  "⊞",
  serverless: "λ",
  iot:        "◎",
  unknown:    "?",
};

/** Tech stack icon mapping (abbreviated) */
export const TECH_ICONS: Record<string, { label: string; color: string }> = {
  apache:       { label: "APH", color: "#D22128" },
  nginx:        { label: "NGX", color: "#009639" },
  iis:          { label: "IIS", color: "#0078D4" },
  tomcat:       { label: "TOM", color: "#F8DC75" },
  wordpress:    { label: "WP",  color: "#21759B" },
  php:          { label: "PHP", color: "#777BB4" },
  java:         { label: "JVA", color: "#ED8B00" },
  python:       { label: "PY",  color: "#3776AB" },
  node:         { label: "NOD", color: "#339933" },
  ".net":       { label: "NET", color: "#512BD4" },
  react:        { label: "RCT", color: "#61DAFB" },
  docker:       { label: "DKR", color: "#2496ED" },
  kubernetes:   { label: "K8S", color: "#326CE5" },
  mysql:        { label: "SQL", color: "#4479A1" },
  postgresql:   { label: "PG",  color: "#4169E1" },
  mongodb:      { label: "MDB", color: "#47A248" },
  redis:        { label: "RDS", color: "#DC382D" },
  elasticsearch:{ label: "ELS", color: "#005571" },
  jenkins:      { label: "JNK", color: "#D24939" },
  spring:       { label: "SPR", color: "#6DB33F" },
  django:       { label: "DJG", color: "#092E20" },
  laravel:      { label: "LRV", color: "#FF2D20" },
};

/** Defense type visual config */
export const DEFENSE_ICONS: Record<string, { label: string; color: string; shape: string }> = {
  waf:      { label: "WAF", color: "#3B82F6", shape: "shield" },
  firewall: { label: "FW",  color: "#2563EB", shape: "shield" },
  edr:      { label: "EDR", color: "#1D4ED8", shape: "shield" },
  ids:      { label: "IDS", color: "#1E40AF", shape: "shield" },
  siem:     { label: "SIM", color: "#1E3A8A", shape: "shield" },
  av:       { label: "AV",  color: "#10B981", shape: "shield" },
  dlp:      { label: "DLP", color: "#06B6D4", shape: "shield" },
  mfa:      { label: "MFA", color: "#8B5CF6", shape: "shield" },
};

// ── Zoom-dependent detail levels ────────────────────────────────────
export const ZOOM_LEVELS = {
  /** Zoomed out: shapes + colors only, no labels */
  MACRO:  { min: 0,    max: 0.4, showLabels: false, showBadges: false, showEdgeLabels: false, showParticles: false },
  /** Medium: labels appear, basic badges */
  MESO:   { min: 0.4,  max: 0.8, showLabels: true,  showBadges: false, showEdgeLabels: false, showParticles: true },
  /** Zoomed in: full detail — labels, badges, edge labels, particles */
  MICRO:  { min: 0.8,  max: 3.0, showLabels: true,  showBadges: true,  showEdgeLabels: true,  showParticles: true },
} as const;

export type ZoomLevel = keyof typeof ZOOM_LEVELS;

export function getZoomLevel(scale: number): ZoomLevel {
  if (scale < ZOOM_LEVELS.MACRO.max) return "MACRO";
  if (scale < ZOOM_LEVELS.MESO.max) return "MESO";
  return "MICRO";
}

// ── Ops Viewer Mode ────────────────────────────────────────────────
export type BattlespaceMode = "engagement" | "di_scan";

// ── Graph Transform Helpers ─────────────────────────────────────────
export interface BattlespaceGraphData {
  nodes: BattlespaceNode[];
  edges: BattlespaceEdge[];
  mode: BattlespaceMode;
  metadata?: {
    engagementName?: string;
    targetDomain?: string;
    scanId?: number;
    threatGroups?: Array<{ id: string; name: string; matchScore: number; threatLevel: string }>;
    killChainCoverage?: Record<KillChainPhase, number>;
    taxonomyCoverage?: { categories: number; protocols: number; techniques: number };
  };
}
