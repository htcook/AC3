/**
 * BloodHound / SharpHound Data Parser
 * Parses SharpHound JSON collection files (v4/v5 format) and ZIP archives
 * to extract AD objects and relationships for the Attack Path Graph.
 */

import { GraphNode, GraphEdge, EdgeType, NodeType, EDGE_WEIGHTS } from "./ad-attack-path-graph";

// ============================================================
// BloodHound JSON Schema Types (SharpHound v4/v5)
// ============================================================

export interface BloodHoundMeta {
  methods: number;
  type: string; // "users" | "groups" | "computers" | "domains" | "gpos" | "ous" | "containers"
  count: number;
  version: number; // 4 or 5
}

export interface BloodHoundCollection {
  meta: BloodHoundMeta;
  data: any[];
}

// ── User Object ──
export interface BHUser {
  ObjectIdentifier: string;
  Properties: {
    name?: string;
    displayname?: string;
    domain?: string;
    distinguishedname?: string;
    samaccountname?: string;
    enabled?: boolean;
    admincount?: boolean;
    hasspn?: boolean;
    dontreqpreauth?: boolean;
    unconstraineddelegation?: boolean;
    lastlogon?: number;
    lastlogontimestamp?: number;
    pwdlastset?: number;
    description?: string;
    sidhistory?: string[];
    highvalue?: boolean;
  };
  PrimaryGroupSID?: string;
  AllowedToDelegate?: { ObjectIdentifier: string; ObjectType: string }[];
  SPNTargets?: { ComputerSID: string; Port: number; Service: string }[];
  HasSIDHistory?: { ObjectIdentifier: string; ObjectType: string }[];
  Aces?: BHAce[];
  IsACLProtected?: boolean;
}

// ── Group Object ──
export interface BHGroup {
  ObjectIdentifier: string;
  Properties: {
    name?: string;
    domain?: string;
    distinguishedname?: string;
    admincount?: boolean;
    description?: string;
    highvalue?: boolean;
  };
  Members?: { ObjectIdentifier: string; ObjectType: string }[];
  Aces?: BHAce[];
  IsACLProtected?: boolean;
}

// ── Computer Object ──
export interface BHComputer {
  ObjectIdentifier: string;
  Properties: {
    name?: string;
    domain?: string;
    distinguishedname?: string;
    enabled?: boolean;
    operatingsystem?: string;
    unconstraineddelegation?: boolean;
    haslaps?: boolean;
    lastlogontimestamp?: number;
    highvalue?: boolean;
  };
  PrimaryGroupSID?: string;
  AllowedToDelegate?: { ObjectIdentifier: string; ObjectType: string }[];
  AllowedToAct?: { ObjectIdentifier: string; ObjectType: string }[];
  Sessions?: { UserSID: string; ComputerSID: string }[];
  PrivilegedSessions?: { UserSID: string; ComputerSID: string }[];
  RegistrySessions?: { UserSID: string; ComputerSID: string }[];
  LocalAdmins?: { ObjectIdentifier: string; ObjectType: string }[];
  RemoteDesktopUsers?: { ObjectIdentifier: string; ObjectType: string }[];
  DcomUsers?: { ObjectIdentifier: string; ObjectType: string }[];
  PSRemoteUsers?: { ObjectIdentifier: string; ObjectType: string }[];
  Aces?: BHAce[];
  IsACLProtected?: boolean;
}

// ── Domain Object ──
export interface BHDomain {
  ObjectIdentifier: string;
  Properties: {
    name?: string;
    domain?: string;
    distinguishedname?: string;
    functionallevel?: string;
    highvalue?: boolean;
  };
  Trusts?: BHTrust[];
  Aces?: BHAce[];
  Links?: { GUID: string; IsEnforced: boolean }[];
  ChildObjects?: { ObjectIdentifier: string; ObjectType: string }[];
}

// ── GPO Object ──
export interface BHGPO {
  ObjectIdentifier: string;
  Properties: {
    name?: string;
    domain?: string;
    distinguishedname?: string;
    gpcpath?: string;
    highvalue?: boolean;
  };
  Aces?: BHAce[];
  IsACLProtected?: boolean;
}

// ── OU Object ──
export interface BHOU {
  ObjectIdentifier: string;
  Properties: {
    name?: string;
    domain?: string;
    distinguishedname?: string;
    highvalue?: boolean;
  };
  Links?: { GUID: string; IsEnforced: boolean }[];
  ChildObjects?: { ObjectIdentifier: string; ObjectType: string }[];
  Aces?: BHAce[];
}

// ── ACE (Access Control Entry) ──
export interface BHAce {
  PrincipalSID: string;
  PrincipalType: string; // "User" | "Group" | "Computer"
  RightName: string;     // "GenericAll" | "WriteDacl" | "WriteOwner" | "GenericWrite" | "ForceChangePassword" | "AddMember" | "Owns" | etc.
  IsInherited: boolean;
}

// ── Trust ──
export interface BHTrust {
  TargetDomainSid: string;
  TargetDomainName: string;
  IsTransitive: boolean;
  TrustDirection: number; // 0=Disabled, 1=Inbound, 2=Outbound, 3=Bidirectional
  TrustType: number;      // 1=WINDOWS_NON_ACTIVE_DIRECTORY, 2=WINDOWS_ACTIVE_DIRECTORY, 3=MIT
  SidFilteringEnabled: boolean;
}

// ============================================================
// ACE Right → Edge Type Mapping
// ============================================================

const ACE_TO_EDGE_MAP: Record<string, EdgeType | null> = {
  "GenericAll": "genericAll",
  "WriteDacl": "writeDacl",
  "WriteOwner": "owns",
  "Owns": "owns",
  "GenericWrite": "writeDacl",
  "ForceChangePassword": "forceChangePassword",
  "AddMember": "addMember",
  "AllExtendedRights": "genericAll",
  "AddAllowedToAct": "delegateTo",
  "ReadLAPSPassword": null,       // informational, not an attack edge
  "ReadGMSAPassword": null,
  "WriteSPN": "kerberoastable",
  "AddKeyCredentialLink": "genericAll",
  "GetChanges": "dcsync",
  "GetChangesAll": "dcsync",
};

// ── BH Object Type → Internal Node Type ──
const BH_TYPE_MAP: Record<string, NodeType> = {
  "User": "user",
  "Group": "group",
  "Computer": "computer",
  "Domain": "domain",
  "GPO": "gpo",
  "OU": "ou",
  "Container": "ou",
  "Base": "domain",
};

// ============================================================
// High-Value Group SIDs (well-known)
// ============================================================

const HIGH_VALUE_SIDS = new Set([
  "-512",  // Domain Admins
  "-516",  // Domain Controllers
  "-519",  // Enterprise Admins
  "-544",  // Administrators (local)
  "-548",  // Account Operators
  "-551",  // Backup Operators
  "-518",  // Schema Admins
  "-527",  // Enterprise Key Admins
]);

function isHighValueSID(sid: string): boolean {
  for (const suffix of Array.from(HIGH_VALUE_SIDS)) {
    if (sid.endsWith(suffix)) return true;
  }
  return false;
}

// ============================================================
// Parse Result
// ============================================================

export interface BloodHoundParseResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: {
    totalUsers: number;
    totalGroups: number;
    totalComputers: number;
    totalDomains: number;
    totalGPOs: number;
    totalOUs: number;
    totalEdges: number;
    totalACEs: number;
    highValueTargets: number;
    kerberoastableUsers: number;
    asrepRoastableUsers: number;
    unconstrainedDelegation: number;
    filesParsed: number;
    parseErrors: string[];
  };
}

export interface ImportProgress {
  phase: "extracting" | "parsing" | "building_graph" | "complete" | "error";
  currentFile?: string;
  filesProcessed: number;
  totalFiles: number;
  objectsProcessed: number;
  message: string;
}

// ============================================================
// SharpHound JSON Parser
// ============================================================

let edgeCounter = 0;

function makeEdge(source: string, target: string, type: EdgeType, props: Record<string, any> = {}): GraphEdge {
  return {
    id: `bh-edge-${edgeCounter++}`,
    source,
    target,
    type,
    weight: EDGE_WEIGHTS[type] ?? 5,
    isExploitable: true,
    properties: props,
  };
}

function calculateRiskScore(obj: any, isPrivileged: boolean): number {
  let score = 0;
  if (isPrivileged) score += 40;
  if (obj.Properties?.admincount) score += 20;
  if (obj.Properties?.highvalue) score += 30;
  if (obj.Properties?.hasspn) score += 10;
  if (obj.Properties?.dontreqpreauth) score += 15;
  if (obj.Properties?.unconstraineddelegation) score += 25;
  if (obj.Properties?.enabled === false) score -= 10;
  return Math.max(0, Math.min(100, score));
}

/**
 * Parse a single SharpHound JSON collection file.
 */
export function parseSharpHoundJSON(jsonContent: string): BloodHoundCollection | null {
  try {
    const parsed = JSON.parse(jsonContent);
    if (!parsed.meta || !parsed.data) {
      // Try v5 format where data might be at root level
      if (Array.isArray(parsed)) {
        return null; // Can't determine type from array alone
      }
      return null;
    }
    return parsed as BloodHoundCollection;
  } catch {
    return null;
  }
}

/**
 * Detect the collection type from filename or meta.
 */
export function detectCollectionType(filename: string, meta?: BloodHoundMeta): string {
  if (meta?.type) return meta.type.toLowerCase();
  const lower = filename.toLowerCase();
  if (lower.includes("users") || lower.includes("user")) return "users";
  if (lower.includes("groups") || lower.includes("group")) return "groups";
  if (lower.includes("computers") || lower.includes("computer")) return "computers";
  if (lower.includes("domains") || lower.includes("domain")) return "domains";
  if (lower.includes("gpos") || lower.includes("gpo")) return "gpos";
  if (lower.includes("ous") || lower.includes("ou")) return "ous";
  if (lower.includes("containers") || lower.includes("container")) return "containers";
  return "unknown";
}

/**
 * Parse ACEs from a BloodHound object and generate edges.
 */
function parseACEs(objectSid: string, aces: BHAce[] | undefined): GraphEdge[] {
  if (!aces || !Array.isArray(aces)) return [];
  const edges: GraphEdge[] = [];
  for (const ace of aces) {
    if (ace.IsInherited) continue; // Skip inherited ACEs for cleaner graphs
    const edgeType = ACE_TO_EDGE_MAP[ace.RightName];
    if (!edgeType) continue;
    // ACE means the PrincipalSID has the right over objectSid
    edges.push(makeEdge(ace.PrincipalSID, objectSid, edgeType, {
      rightName: ace.RightName,
      principalType: ace.PrincipalType,
      isInherited: ace.IsInherited,
    }));
  }
  return edges;
}

/**
 * Parse users collection into graph nodes and edges.
 */
export function parseUsers(data: BHUser[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  for (const user of data) {
    const sid = user.ObjectIdentifier;
    if (!sid) continue;

    const isPrivileged = user.Properties?.admincount || isHighValueSID(sid) || false;
    const isKerberoastable = user.Properties?.hasspn || false;
    const isAsrepRoastable = user.Properties?.dontreqpreauth || false;

    nodes.push({
      id: sid,
      label: user.Properties?.name || user.Properties?.samaccountname || sid,
      type: isPrivileged ? "service_account" : "user",
      isHighValue: user.Properties?.highvalue || isPrivileged,
      isCompromised: false,
      isEnabled: user.Properties?.enabled !== false,
      riskScore: calculateRiskScore(user, isPrivileged),
      properties: {
        domain: user.Properties?.domain,
        displayName: user.Properties?.displayname,
        samAccountName: user.Properties?.samaccountname,
        kerberoastable: isKerberoastable,
        asrepRoastable: isAsrepRoastable,
        unconstrainedDelegation: user.Properties?.unconstraineddelegation,
        lastLogon: user.Properties?.lastlogon,
        pwdLastSet: user.Properties?.pwdlastset,
        description: user.Properties?.description,
        sidHistory: user.Properties?.sidhistory,
      },
    });

    // Primary group membership
    if (user.PrimaryGroupSID) {
      edges.push(makeEdge(sid, user.PrimaryGroupSID, "memberOf"));
    }

    // Delegation targets
    if (user.AllowedToDelegate) {
      for (const target of user.AllowedToDelegate) {
        edges.push(makeEdge(sid, target.ObjectIdentifier, "delegateTo", { objectType: target.ObjectType }));
      }
    }

    // SPN targets (kerberoastable)
    if (user.SPNTargets) {
      for (const spn of user.SPNTargets) {
        edges.push(makeEdge(sid, spn.ComputerSID, "kerberoastable", { port: spn.Port, service: spn.Service }));
      }
    }

    // SID History
    if (user.HasSIDHistory) {
      for (const hist of user.HasSIDHistory) {
        edges.push(makeEdge(sid, hist.ObjectIdentifier, "genericAll", { via: "SIDHistory" }));
      }
    }

    // ACEs
    edges.push(...parseACEs(sid, user.Aces));
  }

  return { nodes, edges };
}

/**
 * Parse groups collection into graph nodes and edges.
 */
export function parseGroups(data: BHGroup[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  for (const group of data) {
    const sid = group.ObjectIdentifier;
    if (!sid) continue;

    const isHighValue = group.Properties?.highvalue || group.Properties?.admincount || isHighValueSID(sid);

    nodes.push({
      id: sid,
      label: group.Properties?.name || sid,
      type: "group",
      isHighValue,
      isCompromised: false,
      isEnabled: true,
      riskScore: isHighValue ? 80 : 20,
      properties: {
        domain: group.Properties?.domain,
        description: group.Properties?.description,
        adminCount: group.Properties?.admincount,
      },
    });

    // Members → group edges
    if (group.Members) {
      for (const member of group.Members) {
        edges.push(makeEdge(member.ObjectIdentifier, sid, "memberOf", { memberType: member.ObjectType }));
      }
    }

    // ACEs
    edges.push(...parseACEs(sid, group.Aces));
  }

  return { nodes, edges };
}

/**
 * Parse computers collection into graph nodes and edges.
 */
export function parseComputers(data: BHComputer[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  for (const comp of data) {
    const sid = comp.ObjectIdentifier;
    if (!sid) continue;

    const isDC = comp.Properties?.name?.includes("DC") || false;
    const isHighValue = comp.Properties?.highvalue || isDC;

    nodes.push({
      id: sid,
      label: comp.Properties?.name || sid,
      type: isDC ? "dc" : "computer",
      isHighValue,
      isCompromised: false,
      isEnabled: comp.Properties?.enabled !== false,
      riskScore: calculateRiskScore(comp, isHighValue),
      properties: {
        domain: comp.Properties?.domain,
        os: comp.Properties?.operatingsystem,
        unconstrainedDelegation: comp.Properties?.unconstraineddelegation,
        hasLAPS: comp.Properties?.haslaps,
        lastLogon: comp.Properties?.lastlogontimestamp,
      },
    });

    // Primary group
    if (comp.PrimaryGroupSID) {
      edges.push(makeEdge(sid, comp.PrimaryGroupSID, "memberOf"));
    }

    // Delegation
    if (comp.AllowedToDelegate) {
      for (const target of comp.AllowedToDelegate) {
        edges.push(makeEdge(sid, target.ObjectIdentifier, "delegateTo"));
      }
    }

    // Resource-based constrained delegation
    if (comp.AllowedToAct) {
      for (const actor of comp.AllowedToAct) {
        edges.push(makeEdge(actor.ObjectIdentifier, sid, "delegateTo", { rbcd: true }));
      }
    }

    // Sessions
    const allSessions = [
      ...(comp.Sessions || []),
      ...(comp.PrivilegedSessions || []),
      ...(comp.RegistrySessions || []),
    ];
    for (const session of allSessions) {
      edges.push(makeEdge(session.UserSID, sid, "hasSession"));
    }

    // Local admins
    if (comp.LocalAdmins) {
      for (const admin of comp.LocalAdmins) {
        edges.push(makeEdge(admin.ObjectIdentifier, sid, "adminTo"));
      }
    }

    // RDP users
    if (comp.RemoteDesktopUsers) {
      for (const rdp of comp.RemoteDesktopUsers) {
        edges.push(makeEdge(rdp.ObjectIdentifier, sid, "canRDP"));
      }
    }

    // PS Remote users
    if (comp.PSRemoteUsers) {
      for (const ps of comp.PSRemoteUsers) {
        edges.push(makeEdge(ps.ObjectIdentifier, sid, "canPsRemote"));
      }
    }

    // ACEs
    edges.push(...parseACEs(sid, comp.Aces));
  }

  return { nodes, edges };
}

/**
 * Parse domains collection into graph nodes and edges.
 */
export function parseDomains(data: BHDomain[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  for (const domain of data) {
    const sid = domain.ObjectIdentifier;
    if (!sid) continue;

    nodes.push({
      id: sid,
      label: domain.Properties?.name || sid,
      type: "domain",
      isHighValue: true,
      isCompromised: false,
      isEnabled: true,
      riskScore: 90,
      properties: {
        domain: domain.Properties?.domain,
        functionalLevel: domain.Properties?.functionallevel,
      },
    });

    // Trusts
    if (domain.Trusts) {
      for (const trust of domain.Trusts) {
        if (trust.TrustDirection === 2 || trust.TrustDirection === 3) {
          // Outbound or bidirectional
          edges.push(makeEdge(sid, trust.TargetDomainSid, "trustedBy", {
            targetDomain: trust.TargetDomainName,
            isTransitive: trust.IsTransitive,
            sidFiltering: trust.SidFilteringEnabled,
            trustType: trust.TrustType,
          }));
        }
        if (trust.TrustDirection === 1 || trust.TrustDirection === 3) {
          // Inbound or bidirectional
          edges.push(makeEdge(trust.TargetDomainSid, sid, "trustedBy", {
            targetDomain: domain.Properties?.name,
            isTransitive: trust.IsTransitive,
            sidFiltering: trust.SidFilteringEnabled,
            trustType: trust.TrustType,
          }));
        }
      }
    }

    // GPO links
    if (domain.Links) {
      for (const link of domain.Links) {
        edges.push(makeEdge(link.GUID, sid, "gpLink", { isEnforced: link.IsEnforced }));
      }
    }

    // Child objects
    if (domain.ChildObjects) {
      for (const child of domain.ChildObjects) {
        edges.push(makeEdge(sid, child.ObjectIdentifier, "contains", { childType: child.ObjectType }));
      }
    }

    // ACEs
    edges.push(...parseACEs(sid, domain.Aces));
  }

  return { nodes, edges };
}

/**
 * Parse GPOs collection into graph nodes and edges.
 */
export function parseGPOs(data: BHGPO[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  for (const gpo of data) {
    const sid = gpo.ObjectIdentifier;
    if (!sid) continue;

    nodes.push({
      id: sid,
      label: gpo.Properties?.name || sid,
      type: "gpo",
      isHighValue: gpo.Properties?.highvalue || false,
      isCompromised: false,
      isEnabled: true,
      riskScore: gpo.Properties?.highvalue ? 60 : 20,
      properties: {
        domain: gpo.Properties?.domain,
        gpcPath: gpo.Properties?.gpcpath,
      },
    });

    // ACEs
    edges.push(...parseACEs(sid, gpo.Aces));
  }

  return { nodes, edges };
}

/**
 * Parse OUs/Containers collection into graph nodes and edges.
 */
export function parseOUs(data: BHOU[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  for (const ou of data) {
    const sid = ou.ObjectIdentifier;
    if (!sid) continue;

    nodes.push({
      id: sid,
      label: ou.Properties?.name || sid,
      type: "ou",
      isHighValue: ou.Properties?.highvalue || false,
      isCompromised: false,
      isEnabled: true,
      riskScore: 10,
      properties: {
        domain: ou.Properties?.domain,
      },
    });

    // GPO links
    if (ou.Links) {
      for (const link of ou.Links) {
        edges.push(makeEdge(link.GUID, sid, "gpLink", { isEnforced: link.IsEnforced }));
      }
    }

    // Child objects
    if (ou.ChildObjects) {
      for (const child of ou.ChildObjects) {
        edges.push(makeEdge(sid, child.ObjectIdentifier, "contains", { childType: child.ObjectType }));
      }
    }

    // ACEs
    edges.push(...parseACEs(sid, ou.Aces));
  }

  return { nodes, edges };
}

// ============================================================
// ZIP Extraction
// ============================================================

/**
 * Extract JSON files from a SharpHound ZIP archive.
 * Returns an array of { filename, content } pairs.
 */
export async function extractSharpHoundZIP(zipBuffer: Buffer): Promise<{ filename: string; content: string }[]> {
  // Use built-in Node.js zlib for ZIP extraction
  const { Readable } = await import("stream");
  const { createUnzip } = await import("zlib");

  // Simple ZIP parser for SharpHound output (which uses standard ZIP format)
  const files: { filename: string; content: string }[] = [];

  // Use a lightweight approach: find local file headers in the ZIP
  let offset = 0;
  while (offset < zipBuffer.length - 4) {
    // Local file header signature: 0x04034b50
    if (
      zipBuffer[offset] === 0x50 &&
      zipBuffer[offset + 1] === 0x4b &&
      zipBuffer[offset + 2] === 0x03 &&
      zipBuffer[offset + 3] === 0x04
    ) {
      const compressionMethod = zipBuffer.readUInt16LE(offset + 8);
      const compressedSize = zipBuffer.readUInt32LE(offset + 18);
      const uncompressedSize = zipBuffer.readUInt32LE(offset + 22);
      const filenameLength = zipBuffer.readUInt16LE(offset + 26);
      const extraLength = zipBuffer.readUInt16LE(offset + 28);
      const filename = zipBuffer.toString("utf8", offset + 30, offset + 30 + filenameLength);
      const dataStart = offset + 30 + filenameLength + extraLength;

      if (filename.endsWith(".json") && compressedSize > 0) {
        const compressedData = zipBuffer.subarray(dataStart, dataStart + compressedSize);

        if (compressionMethod === 0) {
          // Stored (no compression)
          files.push({ filename, content: compressedData.toString("utf8") });
        } else if (compressionMethod === 8) {
          // Deflate
          try {
            const { inflateRawSync } = await import("zlib");
            const decompressed = inflateRawSync(compressedData);
            files.push({ filename, content: decompressed.toString("utf8") });
          } catch (e: any) {
            // Try with full inflate if raw fails
            try {
              const { inflateSync } = await import("zlib");
              const decompressed = inflateSync(compressedData);
              files.push({ filename, content: decompressed.toString("utf8") });
            } catch {
              // Skip corrupted files
            }
          }
        }
      }

      offset = dataStart + compressedSize;
    } else {
      offset++;
    }
  }

  return files;
}

// ============================================================
// Full Import Pipeline
// ============================================================

/**
 * Parse multiple SharpHound JSON files and merge into a unified graph.
 */
export function mergeCollections(
  collections: { filename: string; collection: BloodHoundCollection }[]
): BloodHoundParseResult {
  edgeCounter = 0; // Reset edge counter

  const allNodes: GraphNode[] = [];
  const allEdges: GraphEdge[] = [];
  const nodeIds = new Set<string>();
  const errors: string[] = [];

  let totalACEs = 0;
  let kerberoastable = 0;
  let asrepRoastable = 0;
  let unconstrainedDelegation = 0;
  let userCount = 0;
  let groupCount = 0;
  let computerCount = 0;
  let domainCount = 0;
  let gpoCount = 0;
  let ouCount = 0;

  for (const { filename, collection } of collections) {
    const type = detectCollectionType(filename, collection.meta);
    let parsed: { nodes: GraphNode[]; edges: GraphEdge[] } = { nodes: [], edges: [] };

    try {
      switch (type) {
        case "users":
          parsed = parseUsers(collection.data);
          userCount += collection.data.length;
          for (const user of collection.data) {
            if (user.Properties?.hasspn) kerberoastable++;
            if (user.Properties?.dontreqpreauth) asrepRoastable++;
            if (user.Properties?.unconstraineddelegation) unconstrainedDelegation++;
            if (user.Aces) totalACEs += user.Aces.length;
          }
          break;
        case "groups":
          parsed = parseGroups(collection.data);
          groupCount += collection.data.length;
          for (const g of collection.data) {
            if (g.Aces) totalACEs += g.Aces.length;
          }
          break;
        case "computers":
          parsed = parseComputers(collection.data);
          computerCount += collection.data.length;
          for (const c of collection.data) {
            if (c.Properties?.unconstraineddelegation) unconstrainedDelegation++;
            if (c.Aces) totalACEs += c.Aces.length;
          }
          break;
        case "domains":
          parsed = parseDomains(collection.data);
          domainCount += collection.data.length;
          break;
        case "gpos":
          parsed = parseGPOs(collection.data);
          gpoCount += collection.data.length;
          break;
        case "ous":
        case "containers":
          parsed = parseOUs(collection.data);
          ouCount += collection.data.length;
          break;
        default:
          errors.push(`Unknown collection type "${type}" in file "${filename}"`);
          continue;
      }
    } catch (e: any) {
      errors.push(`Error parsing ${filename}: ${e.message}`);
      continue;
    }

    // Deduplicate nodes by ID
    for (const node of parsed.nodes) {
      if (!nodeIds.has(node.id)) {
        nodeIds.add(node.id);
        allNodes.push(node);
      }
    }
    allEdges.push(...parsed.edges);
  }

  // Deduplicate edges (same source + target + type)
  const edgeKeys = new Set<string>();
  const dedupedEdges: GraphEdge[] = [];
  for (const edge of allEdges) {
    const key = `${edge.source}|${edge.target}|${edge.type}`;
    if (!edgeKeys.has(key)) {
      edgeKeys.add(key);
      dedupedEdges.push(edge);
    }
  }

  return {
    nodes: allNodes,
    edges: dedupedEdges,
    stats: {
      totalUsers: userCount,
      totalGroups: groupCount,
      totalComputers: computerCount,
      totalDomains: domainCount,
      totalGPOs: gpoCount,
      totalOUs: ouCount,
      totalEdges: dedupedEdges.length,
      totalACEs: totalACEs,
      highValueTargets: allNodes.filter(n => n.isHighValue).length,
      kerberoastableUsers: kerberoastable,
      asrepRoastableUsers: asrepRoastable,
      unconstrainedDelegation: unconstrainedDelegation,
      filesParsed: collections.length,
      parseErrors: errors,
    },
  };
}

/**
 * Full import pipeline: takes raw file data (JSON or ZIP), parses, and returns unified graph.
 */
export async function importBloodHoundData(
  files: { filename: string; data: Buffer | string }[]
): Promise<BloodHoundParseResult> {
  const collections: { filename: string; collection: BloodHoundCollection }[] = [];
  const errors: string[] = [];

  for (const file of files) {
    const isZip = file.filename.toLowerCase().endsWith(".zip") ||
      (Buffer.isBuffer(file.data) && file.data[0] === 0x50 && file.data[1] === 0x4b);

    if (isZip) {
      // Extract ZIP and parse each JSON file
      const buf = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data, "base64");
      try {
        const extracted = await extractSharpHoundZIP(buf);
        for (const { filename, content } of extracted) {
          const collection = parseSharpHoundJSON(content);
          if (collection) {
            collections.push({ filename, collection });
          } else {
            errors.push(`Failed to parse JSON from ZIP entry: ${filename}`);
          }
        }
      } catch (e: any) {
        errors.push(`Failed to extract ZIP ${file.filename}: ${e.message}`);
      }
    } else {
      // Parse as JSON directly
      const content = Buffer.isBuffer(file.data) ? file.data.toString("utf8") : file.data;
      const collection = parseSharpHoundJSON(content);
      if (collection) {
        collections.push({ filename: file.filename, collection });
      } else {
        errors.push(`Failed to parse JSON: ${file.filename}`);
      }
    }
  }

  const result = mergeCollections(collections);
  result.stats.parseErrors.push(...errors);
  return result;
}
