import { TRPCError } from "@trpc/server";
import { and, eq } from "drizzle-orm";
import { engagements } from "../../drizzle/schema";
import { extractHostname, parseTargets, validateEngagementTargets, type DomainValidationResult } from "../../shared/domain-safety-whitelist";

/**
 * The fields that authorize active or exploit-capable work. Keep this independent
 * from request data: active authorization must be persisted on the engagement.
 */
export interface ActiveEngagementAuthorizationContext {
  targetDomain?: string | null;
  targetIpRange?: string | null;
  roeStatus?: "none" | "pending" | "signed" | "expired" | string | null;
  roeExpiryDate?: string | Date | null;
  activeScanOverride?: number | boolean | null;
}

/**
 * Load an engagement only when it belongs to the active request tenant.
 * A missing tenant assignment deliberately behaves as not found.
 */
export async function getEngagementForTenant(db: any, engagementId: number, tenantId: number) {
  const [engagement] = await db
    .select()
    .from(engagements)
    .where(and(
      eq(engagements.id, engagementId),
      eq(engagements.engTenantId, tenantId),
    ))
    .limit(1);

  if (!engagement) {
    throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });
  }

  return engagement;
}

/**
 * Require explicit, currently valid authorization before an operation can scan,
 * exploit, authenticate against, or otherwise actively interact with a target.
 * Passive DI/OSINT callers must not invoke this helper.
 */
export function assertActiveEngagementAuthorization(
  engagement: ActiveEngagementAuthorizationContext,
  now = new Date(),
): DomainValidationResult {
  if (engagement.roeStatus !== "signed") {
    throw new TRPCError({
      code: "PRECONDITION_FAILED",
      message: "A signed Rules of Engagement is required before active scanning or exploitation.",
    });
  }

  if (engagement.roeExpiryDate) {
    const expiry = new Date(engagement.roeExpiryDate);
    if (!Number.isNaN(expiry.getTime()) && expiry.getTime() <= now.getTime()) {
      throw new TRPCError({
        code: "PRECONDITION_FAILED",
        message: "The Rules of Engagement has expired. Renew it before active scanning or exploitation.",
      });
    }
  }

  const targetCheck = validateEngagementTargets(engagement.targetDomain, engagement.targetIpRange);
  if (targetCheck.totalTargets === 0) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "No targets defined. Add target domains or IP ranges first.",
    });
  }

  if (!targetCheck.allWhitelisted && Number(engagement.activeScanOverride) !== 1) {
    throw new TRPCError({
      code: "FORBIDDEN",
      message:
        `SAFETY GUARDRAIL: Cannot start active work — ${targetCheck.nonWhitelistedCount} target(s) are not on the approved test lab whitelist: ` +
        `${targetCheck.nonWhitelistedTargets.join(", ")}. Only passive reconnaissance is permitted until a signed RoE is paired with an approved active-scan override.`,
    });
  }

  return targetCheck;
}

function ipv4ToInteger(value: string): number | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (
    octets[0] * 0x1000000 +
    octets[1] * 0x10000 +
    octets[2] * 0x100 +
    octets[3]
  ) >>> 0;
}

function targetMatchesScope(targetHost: string, scopeTarget: string): boolean {
  const target = extractHostname(targetHost);
  const scope = extractHostname(scopeTarget);
  if (!target || !scope) return false;
  if (target === scope || target.endsWith(`.${scope}`)) return true;

  const cidr = scopeTarget.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[12]\d|3[0-2])$/);
  if (!cidr) return false;
  const candidate = ipv4ToInteger(target);
  const network = ipv4ToInteger(cidr[1]);
  if (candidate === null || network === null) return false;
  const prefix = Number(cidr[2]);
  const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0);
  return (candidate & mask) === (network & mask);
}

/** Require an explicitly named active target to fall within the engagement scope. */
export function assertTargetWithinEngagementScope(
  engagement: Pick<ActiveEngagementAuthorizationContext, "targetDomain" | "targetIpRange">,
  targetHost: string,
): void {
  const targets = [
    ...parseTargets(engagement.targetDomain || ""),
    ...parseTargets(engagement.targetIpRange || ""),
  ];
  if (!targets.some((scopeTarget) => targetMatchesScope(targetHost, scopeTarget))) {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: "The requested target is outside this engagement's authorized scope.",
    });
  }
}
