import {
  NOT_ADMIN_ERR_MSG,
  UNAUTHED_ERR_MSG,
  init_const
} from "./chunk-SOJRLK5Z.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/_core/trpc.ts
import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
var t, router, publicProcedure, requireUser, protectedProcedure, adminProcedure, requireTenant, tenantProcedure, requireAdminTenant, adminTenantProcedure;
var init_trpc = __esm({
  "server/_core/trpc.ts"() {
    "use strict";
    init_const();
    t = initTRPC.context().create({
      transformer: superjson
    });
    router = t.router;
    publicProcedure = t.procedure;
    requireUser = t.middleware(async (opts) => {
      const { ctx, next } = opts;
      if (!ctx.user) {
        throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
      }
      return next({
        ctx: {
          ...ctx,
          user: ctx.user
        }
      });
    });
    protectedProcedure = t.procedure.use(requireUser);
    adminProcedure = t.procedure.use(
      t.middleware(async (opts) => {
        const { ctx, next } = opts;
        if (!ctx.user || ctx.user.role !== "admin") {
          throw new TRPCError({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
        }
        return next({
          ctx: {
            ...ctx,
            user: ctx.user
          }
        });
      })
    );
    requireTenant = t.middleware(async (opts) => {
      const { ctx, next } = opts;
      if (!ctx.user) {
        throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
      }
      const { resolveUserTenant, autoProvisionTenant } = await import("./tenant-isolation-GFI34K5D.js");
      const requestedTenantId = ctx.req.headers["x-tenant-id"] ? parseInt(ctx.req.headers["x-tenant-id"], 10) : null;
      let tenant = await resolveUserTenant(ctx.user.id, requestedTenantId || null);
      if (!tenant) {
        try {
          tenant = await autoProvisionTenant(ctx.user.id, ctx.user.name);
        } catch {
          throw new TRPCError({
            code: "INTERNAL_SERVER_ERROR",
            message: "Failed to provision tenant workspace"
          });
        }
      }
      return next({
        ctx: {
          ...ctx,
          user: ctx.user,
          tenant
        }
      });
    });
    tenantProcedure = t.procedure.use(requireTenant);
    requireAdminTenant = t.middleware(async (opts) => {
      const { ctx, next } = opts;
      if (!ctx.user || ctx.user.role !== "admin") {
        throw new TRPCError({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
      }
      const { resolveUserTenant, autoProvisionTenant } = await import("./tenant-isolation-GFI34K5D.js");
      const requestedTenantId = ctx.req.headers["x-tenant-id"] ? parseInt(ctx.req.headers["x-tenant-id"], 10) : null;
      let tenant = await resolveUserTenant(ctx.user.id, requestedTenantId || null);
      if (!tenant) {
        try {
          tenant = await autoProvisionTenant(ctx.user.id, ctx.user.name);
        } catch {
          throw new TRPCError({
            code: "INTERNAL_SERVER_ERROR",
            message: "Failed to provision tenant workspace"
          });
        }
      }
      return next({
        ctx: {
          ...ctx,
          user: ctx.user,
          tenant
        }
      });
    });
    adminTenantProcedure = t.procedure.use(requireAdminTenant);
  }
});

export {
  router,
  publicProcedure,
  protectedProcedure,
  adminProcedure,
  tenantProcedure,
  adminTenantProcedure,
  init_trpc
};
