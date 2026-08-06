import { NOT_ADMIN_ERR_MSG, UNAUTHED_ERR_MSG } from '@shared/const';
import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import type { TrpcContext } from "./context";
import type { TenantContext } from "../lib/tenant-isolation";

const t = initTRPC.context<TrpcContext>().create({
  transformer: superjson,
});

export const router = t.router;
export const publicProcedure = t.procedure;

const requireUser = t.middleware(async opts => {
  const { ctx, next } = opts;

  if (!ctx.user) {
    throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }

  return next({
    ctx: {
      ...ctx,
      user: ctx.user,
    },
  });
});

export const protectedProcedure = t.procedure.use(requireUser);

export const adminProcedure = t.procedure.use(
  t.middleware(async opts => {
    const { ctx, next } = opts;

    if (!ctx.user || ctx.user.role !== 'admin') {
      throw new TRPCError({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
    }

    return next({
      ctx: {
        ...ctx,
        user: ctx.user,
      },
    });
  }),
);

/**
 * Tenant-scoped procedure — resolves the user's active tenant and injects
 * tenantId + tenantRole into the context. Use this for any procedure that
 * accesses tenant-scoped data.
 *
 * If the user has no tenant membership, auto-provisions a default tenant.
 * The X-Tenant-Id header can be used to switch between tenants.
 */
const requireTenant = t.middleware(async opts => {
  const { ctx, next } = opts;
  if (!ctx.user) {
    throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }

  const { resolveUserTenant, autoProvisionTenant } = await import("../lib/tenant-isolation");

  const requestedTenantId = ctx.req.headers["x-tenant-id"]
    ? parseInt(ctx.req.headers["x-tenant-id"] as string, 10)
    : null;

  let tenant = await resolveUserTenant(ctx.user.id, requestedTenantId || null);

  if (!tenant) {
    try {
      tenant = await autoProvisionTenant(ctx.user.id, ctx.user.name);
    } catch {
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to provision tenant workspace",
      });
    }
  }

  return next({
    ctx: {
      ...ctx,
      user: ctx.user,
      tenant,
    },
  });
});

export const tenantProcedure = t.procedure.use(requireTenant);

/**
 * Admin + tenant-scoped procedure.
 */
const requireAdminTenant = t.middleware(async opts => {
  const { ctx, next } = opts;
  if (!ctx.user || ctx.user.role !== 'admin') {
    throw new TRPCError({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
  }

  const { resolveUserTenant, autoProvisionTenant } = await import("../lib/tenant-isolation");
  const requestedTenantId = ctx.req.headers["x-tenant-id"]
    ? parseInt(ctx.req.headers["x-tenant-id"] as string, 10)
    : null;

  let tenant = await resolveUserTenant(ctx.user.id, requestedTenantId || null);
  if (!tenant) {
    try {
      tenant = await autoProvisionTenant(ctx.user.id, ctx.user.name);
    } catch {
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to provision tenant workspace",
      });
    }
  }

  return next({
    ctx: {
      ...ctx,
      user: ctx.user,
      tenant,
    },
  });
});

export const adminTenantProcedure = t.procedure.use(requireAdminTenant);
