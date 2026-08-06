/**
 * Active Directory Domain Connector
 * Integrates LDAP/LDAPS to pull real AD objects (users, groups, computers,
 * GPOs, OUs, trusts, SPNs, certificate templates) into the AD Attack
 * Simulation module for live attack path analysis.
 */
import ldap from "ldapjs";

// ── Types ───────────────────────────────────────────────────────────────────

export interface LDAPConnectionConfig {
  serverHost: string;
  serverPort: number;
  useTls: boolean;
  tlsRejectUnauthorized: boolean;
  baseDn: string;
  bindDn?: string;
  bindPassword?: string;
}

export interface ADObject {
  objectType: "user" | "group" | "computer" | "gpo" | "ou" | "trust" | "spn" | "certificate_template";
  distinguishedName: string;
  samAccountName?: string;
  displayName?: string;
  isPrivileged: boolean;
  isEnabled: boolean;
  memberOf?: string[];
  members?: string[];
  properties?: Record<string, any>;
}

export interface ADEnumerationResult {
  users: ADObject[];
  groups: ADObject[];
  computers: ADObject[];
  gpos: ADObject[];
  ous: ADObject[];
  trusts: ADObject[];
  spns: ADObject[];
  certificateTemplates: ADObject[];
  summary: {
    totalUsers: number;
    totalGroups: number;
    totalComputers: number;
    totalGpos: number;
    totalOus: number;
    totalTrusts: number;
    totalSpns: number;
    privilegedUsers: number;
    kerberoastableUsers: number;
    asrepRoastableUsers: number;
    disabledAccounts: number;
  };
  errors: string[];
}

// ── Privileged Group SIDs ───────────────────────────────────────────────────

const PRIVILEGED_GROUPS = [
  "Domain Admins", "Enterprise Admins", "Schema Admins",
  "Administrators", "Account Operators", "Backup Operators",
  "Server Operators", "Print Operators", "DnsAdmins",
  "Group Policy Creator Owners", "Cert Publishers",
];

const PRIVILEGED_GROUP_DNS_PATTERNS = PRIVILEGED_GROUPS.map(g => g.toLowerCase());

// ── LDAP Client Helpers ─────────────────────────────────────────────────────

function createLDAPClient(config: LDAPConnectionConfig): Promise<ldap.Client> {
  return new Promise((resolve, reject) => {
    const protocol = config.useTls ? "ldaps" : "ldap";
    const url = `${protocol}://${config.serverHost}:${config.serverPort}`;

    const tlsOptions = config.useTls ? {
      rejectUnauthorized: config.tlsRejectUnauthorized,
    } : undefined;

    const client = ldap.createClient({
      url,
      tlsOptions,
      timeout: 30000,
      connectTimeout: 15000,
    });

    client.on("error", (err: Error) => {
      reject(new Error(`LDAP connection error: ${err.message}`));
    });

    client.on("connect", () => {
      resolve(client);
    });

    // Timeout fallback
    setTimeout(() => {
      reject(new Error("LDAP connection timeout after 15 seconds"));
    }, 15000);
  });
}

function bindClient(client: ldap.Client, bindDn: string, password: string): Promise<void> {
  return new Promise((resolve, reject) => {
    client.bind(bindDn, password, (err: Error | null) => {
      if (err) reject(new Error(`LDAP bind failed: ${err.message}`));
      else resolve();
    });
  });
}

function ldapSearch(client: ldap.Client, baseDn: string, options: ldap.SearchOptions): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const results: any[] = [];
    client.search(baseDn, options, (err: Error | null, res: ldap.SearchCallbackResponse) => {
      if (err) {
        reject(new Error(`LDAP search failed: ${err.message}`));
        return;
      }
      res.on("searchEntry", (entry: ldap.SearchEntry) => {
        const obj: Record<string, any> = {};
        // Use pojo property for ldapjs v3
        const pojo = entry.pojo || entry;
        if (entry.attributes) {
          for (const attr of entry.attributes) {
            const vals = attr.values;
            obj[attr.type] = vals.length === 1 ? vals[0] : vals;
          }
        }
        obj.dn = entry.objectName || (entry as any).dn?.toString() || "";
        results.push(obj);
      });
      res.on("error", (searchErr: Error) => {
        reject(new Error(`LDAP search error: ${searchErr.message}`));
      });
      res.on("end", () => {
        resolve(results);
      });
    });
  });
}

function unbindClient(client: ldap.Client): Promise<void> {
  return new Promise((resolve) => {
    client.unbind(() => resolve());
  });
}

// ── Connection Test ─────────────────────────────────────────────────────────

export async function testConnection(config: LDAPConnectionConfig): Promise<{
  success: boolean;
  message: string;
  serverInfo?: any;
}> {
  let client: ldap.Client | null = null;
  try {
    client = await createLDAPClient(config);

    if (config.bindDn && config.bindPassword) {
      await bindClient(client, config.bindDn, config.bindPassword);
    }

    // Try a simple search to verify
    const results = await ldapSearch(client, config.baseDn, {
      scope: "base",
      filter: "(objectClass=*)",
      attributes: ["defaultNamingContext", "dnsHostName", "forestFunctionality", "domainFunctionality"],
    });

    return {
      success: true,
      message: "Connection successful",
      serverInfo: results[0] || {},
    };
  } catch (e: any) {
    return {
      success: false,
      message: e.message,
    };
  } finally {
    if (client) {
      try { await unbindClient(client); } catch { /* ignore */ }
    }
  }
}

// ── Full Enumeration ────────────────────────────────────────────────────────

export async function enumerateADDomain(
  config: LDAPConnectionConfig,
  scope: "full" | "users" | "groups" | "computers" | "gpos" | "ous" | "trusts" | "spns" | "certificates" = "full"
): Promise<ADEnumerationResult> {
  const errors: string[] = [];
  const result: ADEnumerationResult = {
    users: [], groups: [], computers: [], gpos: [], ous: [],
    trusts: [], spns: [], certificateTemplates: [],
    summary: {
      totalUsers: 0, totalGroups: 0, totalComputers: 0,
      totalGpos: 0, totalOus: 0, totalTrusts: 0, totalSpns: 0,
      privilegedUsers: 0, kerberoastableUsers: 0,
      asrepRoastableUsers: 0, disabledAccounts: 0,
    },
    errors,
  };

  let client: ldap.Client | null = null;
  try {
    client = await createLDAPClient(config);

    if (config.bindDn && config.bindPassword) {
      await bindClient(client, config.bindDn, config.bindPassword);
    }

    const baseDn = config.baseDn;

    // ── Users ─────────────────────────────────────────────────────────────
    if (scope === "full" || scope === "users") {
      try {
        const users = await ldapSearch(client, baseDn, {
          scope: "sub",
          filter: "(&(objectCategory=person)(objectClass=user))",
          attributes: [
            "distinguishedName", "sAMAccountName", "displayName", "mail",
            "memberOf", "userAccountControl", "servicePrincipalName",
            "adminCount", "lastLogonTimestamp", "pwdLastSet", "whenCreated",
            "description", "title", "department",
          ],
          sizeLimit: 10000,
        });

        for (const u of users) {
          const uac = parseInt(u.userAccountControl || "0", 10);
          const isEnabled = !(uac & 0x0002); // ACCOUNTDISABLE
          const isKerberoastable = !!u.servicePrincipalName && isEnabled;
          const isAsrepRoastable = !!(uac & 0x400000) && isEnabled; // DONT_REQUIRE_PREAUTH
          const memberOfList = Array.isArray(u.memberOf) ? u.memberOf : (u.memberOf ? [u.memberOf] : []);
          const isPrivileged = !!(u.adminCount === "1" || memberOfList.some((g: string) =>
            PRIVILEGED_GROUP_DNS_PATTERNS.some(pg => g.toLowerCase().includes(pg))
          ));

          result.users.push({
            objectType: "user",
            distinguishedName: u.dn || u.distinguishedName,
            samAccountName: u.sAMAccountName,
            displayName: u.displayName || u.sAMAccountName,
            isPrivileged,
            isEnabled,
            memberOf: memberOfList,
            properties: {
              mail: u.mail,
              isKerberoastable,
              isAsrepRoastable,
              spns: Array.isArray(u.servicePrincipalName) ? u.servicePrincipalName : (u.servicePrincipalName ? [u.servicePrincipalName] : []),
              lastLogon: u.lastLogonTimestamp,
              pwdLastSet: u.pwdLastSet,
              whenCreated: u.whenCreated,
              description: u.description,
              title: u.title,
              department: u.department,
            },
          });

          if (isPrivileged) result.summary.privilegedUsers++;
          if (isKerberoastable) result.summary.kerberoastableUsers++;
          if (isAsrepRoastable) result.summary.asrepRoastableUsers++;
          if (!isEnabled) result.summary.disabledAccounts++;
        }
        result.summary.totalUsers = result.users.length;
      } catch (e: any) {
        errors.push(`User enumeration failed: ${e.message}`);
      }
    }

    // ── Groups ────────────────────────────────────────────────────────────
    if (scope === "full" || scope === "groups") {
      try {
        const groups = await ldapSearch(client, baseDn, {
          scope: "sub",
          filter: "(objectCategory=group)",
          attributes: [
            "distinguishedName", "sAMAccountName", "displayName",
            "member", "memberOf", "groupType", "adminCount", "description",
          ],
          sizeLimit: 5000,
        });

        for (const g of groups) {
          const memberList = Array.isArray(g.member) ? g.member : (g.member ? [g.member] : []);
          const memberOfList = Array.isArray(g.memberOf) ? g.memberOf : (g.memberOf ? [g.memberOf] : []);
          const isPrivileged = !!(g.adminCount === "1" ||
            PRIVILEGED_GROUP_DNS_PATTERNS.some(pg => (g.sAMAccountName || "").toLowerCase().includes(pg)));

          result.groups.push({
            objectType: "group",
            distinguishedName: g.dn || g.distinguishedName,
            samAccountName: g.sAMAccountName,
            displayName: g.displayName || g.sAMAccountName,
            isPrivileged,
            isEnabled: true,
            memberOf: memberOfList,
            members: memberList,
            properties: {
              groupType: g.groupType,
              memberCount: memberList.length,
              description: g.description,
            },
          });
        }
        result.summary.totalGroups = result.groups.length;
      } catch (e: any) {
        errors.push(`Group enumeration failed: ${e.message}`);
      }
    }

    // ── Computers ─────────────────────────────────────────────────────────
    if (scope === "full" || scope === "computers") {
      try {
        const computers = await ldapSearch(client, baseDn, {
          scope: "sub",
          filter: "(objectCategory=computer)",
          attributes: [
            "distinguishedName", "sAMAccountName", "displayName",
            "operatingSystem", "operatingSystemVersion", "dNSHostName",
            "userAccountControl", "lastLogonTimestamp", "whenCreated",
            "servicePrincipalName", "memberOf",
          ],
          sizeLimit: 10000,
        });

        for (const c of computers) {
          const uac = parseInt(c.userAccountControl || "0", 10);
          const isEnabled = !(uac & 0x0002);
          const memberOfList = Array.isArray(c.memberOf) ? c.memberOf : (c.memberOf ? [c.memberOf] : []);
          const isDC = memberOfList.some((g: string) => g.toLowerCase().includes("domain controllers"));

          result.computers.push({
            objectType: "computer",
            distinguishedName: c.dn || c.distinguishedName,
            samAccountName: c.sAMAccountName,
            displayName: c.dNSHostName || c.sAMAccountName,
            isPrivileged: isDC,
            isEnabled,
            memberOf: memberOfList,
            properties: {
              os: c.operatingSystem,
              osVersion: c.operatingSystemVersion,
              dnsHostName: c.dNSHostName,
              isDomainController: isDC,
              lastLogon: c.lastLogonTimestamp,
              whenCreated: c.whenCreated,
              spns: Array.isArray(c.servicePrincipalName) ? c.servicePrincipalName : (c.servicePrincipalName ? [c.servicePrincipalName] : []),
            },
          });
        }
        result.summary.totalComputers = result.computers.length;
      } catch (e: any) {
        errors.push(`Computer enumeration failed: ${e.message}`);
      }
    }

    // ── GPOs ──────────────────────────────────────────────────────────────
    if (scope === "full" || scope === "gpos") {
      try {
        const gpos = await ldapSearch(client, baseDn, {
          scope: "sub",
          filter: "(objectClass=groupPolicyContainer)",
          attributes: [
            "distinguishedName", "displayName", "gPCFileSysPath",
            "versionNumber", "flags", "whenCreated", "whenChanged",
          ],
          sizeLimit: 5000,
        });

        for (const gpo of gpos) {
          result.gpos.push({
            objectType: "gpo",
            distinguishedName: gpo.dn || gpo.distinguishedName,
            displayName: gpo.displayName || "Unnamed GPO",
            isPrivileged: false,
            isEnabled: gpo.flags !== "3", // flags=3 means disabled
            properties: {
              fileSysPath: gpo.gPCFileSysPath,
              version: gpo.versionNumber,
              flags: gpo.flags,
              whenCreated: gpo.whenCreated,
              whenChanged: gpo.whenChanged,
            },
          });
        }
        result.summary.totalGpos = result.gpos.length;
      } catch (e: any) {
        errors.push(`GPO enumeration failed: ${e.message}`);
      }
    }

    // ── OUs ───────────────────────────────────────────────────────────────
    if (scope === "full" || scope === "ous") {
      try {
        const ous = await ldapSearch(client, baseDn, {
          scope: "sub",
          filter: "(objectClass=organizationalUnit)",
          attributes: [
            "distinguishedName", "name", "description",
            "gPLink", "whenCreated",
          ],
          sizeLimit: 5000,
        });

        for (const ou of ous) {
          result.ous.push({
            objectType: "ou",
            distinguishedName: ou.dn || ou.distinguishedName,
            displayName: ou.name || "Unnamed OU",
            isPrivileged: false,
            isEnabled: true,
            properties: {
              description: ou.description,
              linkedGPOs: ou.gPLink,
              whenCreated: ou.whenCreated,
            },
          });
        }
        result.summary.totalOus = result.ous.length;
      } catch (e: any) {
        errors.push(`OU enumeration failed: ${e.message}`);
      }
    }

    // ── Trusts ────────────────────────────────────────────────────────────
    if (scope === "full" || scope === "trusts") {
      try {
        const trusts = await ldapSearch(client, baseDn, {
          scope: "sub",
          filter: "(objectClass=trustedDomain)",
          attributes: [
            "distinguishedName", "name", "trustDirection",
            "trustType", "trustAttributes", "flatName",
            "securityIdentifier", "whenCreated",
          ],
          sizeLimit: 100,
        });

        for (const trust of trusts) {
          const direction = parseInt(trust.trustDirection || "0", 10);
          const directionLabel = direction === 1 ? "Inbound" : direction === 2 ? "Outbound" : direction === 3 ? "Bidirectional" : "Unknown";

          result.trusts.push({
            objectType: "trust",
            distinguishedName: trust.dn || trust.distinguishedName,
            displayName: trust.name || trust.flatName || "Unknown Trust",
            isPrivileged: false,
            isEnabled: true,
            properties: {
              direction: directionLabel,
              trustType: trust.trustType,
              trustAttributes: trust.trustAttributes,
              flatName: trust.flatName,
              whenCreated: trust.whenCreated,
            },
          });
        }
        result.summary.totalTrusts = result.trusts.length;
      } catch (e: any) {
        errors.push(`Trust enumeration failed: ${e.message}`);
      }
    }

    // ── SPNs (from users with servicePrincipalName) ─────────────────────
    if (scope === "full" || scope === "spns") {
      try {
        const spnUsers = await ldapSearch(client, baseDn, {
          scope: "sub",
          filter: "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
          attributes: [
            "distinguishedName", "sAMAccountName", "displayName",
            "servicePrincipalName", "userAccountControl",
          ],
          sizeLimit: 5000,
        });

        for (const u of spnUsers) {
          const spns = Array.isArray(u.servicePrincipalName) ? u.servicePrincipalName : [u.servicePrincipalName];
          for (const spn of spns) {
            result.spns.push({
              objectType: "spn",
              distinguishedName: u.dn || u.distinguishedName,
              samAccountName: u.sAMAccountName,
              displayName: `${u.sAMAccountName}: ${spn}`,
              isPrivileged: false,
              isEnabled: true,
              properties: { spn, owner: u.sAMAccountName },
            });
          }
        }
        result.summary.totalSpns = result.spns.length;
      } catch (e: any) {
        errors.push(`SPN enumeration failed: ${e.message}`);
      }
    }

    // ── Certificate Templates ───────────────────────────────────────────
    if (scope === "full" || scope === "certificates") {
      try {
        // Certificate templates are in the Configuration naming context
        const configDn = `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,${baseDn}`;
        const templates = await ldapSearch(client, configDn, {
          scope: "sub",
          filter: "(objectClass=pKICertificateTemplate)",
          attributes: [
            "distinguishedName", "name", "displayName",
            "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
            "msPKI-Private-Key-Flag", "pKIExtendedKeyUsage",
            "msPKI-Certificate-Application-Policy",
          ],
          sizeLimit: 500,
        });

        for (const tmpl of templates) {
          const enrollFlag = parseInt(tmpl["msPKI-Enrollment-Flag"] || "0", 10);
          const nameFlag = parseInt(tmpl["msPKI-Certificate-Name-Flag"] || "0", 10);
          // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
          const suppliesSubject = !!(nameFlag & 0x1);

          result.certificateTemplates.push({
            objectType: "certificate_template",
            distinguishedName: tmpl.dn || tmpl.distinguishedName,
            displayName: tmpl.displayName || tmpl.name,
            isPrivileged: false,
            isEnabled: true,
            properties: {
              enrollmentFlag: enrollFlag,
              nameFlag: nameFlag,
              suppliesSubject,
              ekus: tmpl.pKIExtendedKeyUsage,
              applicationPolicies: tmpl["msPKI-Certificate-Application-Policy"],
              isVulnerable: suppliesSubject, // ESC1-like vulnerability
            },
          });
        }
      } catch (e: any) {
        // Certificate template enumeration may fail if not in config context
        errors.push(`Certificate template enumeration: ${e.message}`);
      }
    }

  } catch (e: any) {
    errors.push(`AD enumeration error: ${e.message}`);
  } finally {
    if (client) {
      try { await unbindClient(client); } catch { /* ignore */ }
    }
  }

  return result;
}

// ── Attack Surface Analysis ─────────────────────────────────────────────────

export interface ADAttackSurface {
  kerberoastTargets: ADObject[];
  asrepRoastTargets: ADObject[];
  privilegedAccounts: ADObject[];
  unconstrained: ADObject[];
  vulnerableCertTemplates: ADObject[];
  domainControllers: ADObject[];
  staleAccounts: ADObject[];
  trustRelationships: ADObject[];
  riskScore: number;
  riskFactors: string[];
}

export function analyzeAttackSurface(enumResult: ADEnumerationResult): ADAttackSurface {
  const riskFactors: string[] = [];

  const kerberoastTargets = enumResult.users.filter(u => u.properties?.isKerberoastable);
  if (kerberoastTargets.length > 0) {
    riskFactors.push(`${kerberoastTargets.length} Kerberoastable accounts found`);
  }

  const asrepRoastTargets = enumResult.users.filter(u => u.properties?.isAsrepRoastable);
  if (asrepRoastTargets.length > 0) {
    riskFactors.push(`${asrepRoastTargets.length} AS-REP Roastable accounts found`);
  }

  const privilegedAccounts = enumResult.users.filter(u => u.isPrivileged);
  if (privilegedAccounts.length > 10) {
    riskFactors.push(`Excessive privileged accounts: ${privilegedAccounts.length}`);
  }

  const unconstrained = enumResult.computers.filter(c =>
    c.properties?.spns?.some((s: string) => s.includes("HOST/")) && !c.properties?.isDomainController
  );

  const vulnerableCertTemplates = enumResult.certificateTemplates.filter(t => t.properties?.isVulnerable);
  if (vulnerableCertTemplates.length > 0) {
    riskFactors.push(`${vulnerableCertTemplates.length} vulnerable certificate templates (ESC1-like)`);
  }

  const domainControllers = enumResult.computers.filter(c => c.properties?.isDomainController);

  const staleAccounts = enumResult.users.filter(u => {
    if (!u.isEnabled) return false;
    const lastLogon = u.properties?.lastLogon;
    if (!lastLogon) return true; // Never logged in
    // Windows FILETIME to JS Date
    const logonDate = new Date(parseInt(lastLogon, 10) / 10000 - 11644473600000);
    return Date.now() - logonDate.getTime() > 180 * 24 * 60 * 60 * 1000; // 180 days
  });
  if (staleAccounts.length > 0) {
    riskFactors.push(`${staleAccounts.length} stale accounts (no login >180 days)`);
  }

  if (enumResult.trusts.length > 0) {
    riskFactors.push(`${enumResult.trusts.length} domain trust relationships`);
  }

  // Calculate risk score (0-100)
  let riskScore = 0;
  riskScore += Math.min(kerberoastTargets.length * 5, 25);
  riskScore += Math.min(asrepRoastTargets.length * 8, 20);
  riskScore += privilegedAccounts.length > 10 ? 15 : privilegedAccounts.length > 5 ? 8 : 0;
  riskScore += vulnerableCertTemplates.length * 10;
  riskScore += staleAccounts.length > 50 ? 10 : staleAccounts.length > 20 ? 5 : 0;
  riskScore += enumResult.trusts.length * 3;
  riskScore += enumResult.summary.disabledAccounts > 100 ? 5 : 0;
  riskScore = Math.min(riskScore, 100);

  return {
    kerberoastTargets,
    asrepRoastTargets,
    privilegedAccounts,
    unconstrained,
    vulnerableCertTemplates,
    domainControllers,
    staleAccounts,
    trustRelationships: enumResult.trusts,
    riskScore,
    riskFactors,
  };
}
