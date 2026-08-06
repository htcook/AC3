import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  generateInstaller,
  getSupportedPlatforms,
  getAllProfiles,
  getCapabilitiesForProfile,
  type AgentInstallerConfig,
  type AgentPlatform,
  type AgentProfile,
  type BeaconProtocol,
} from "../lib/agent-installer-generator";

export const agentInstallerRouter = router({
  /** List supported agent platforms */
  listPlatforms: protectedProcedure.query(() => {
    return getSupportedPlatforms();
  }),

  /** List all agent profiles */
  listProfiles: protectedProcedure.query(() => {
    return getAllProfiles();
  }),

  /** Get capabilities for a specific profile */
  getProfileCapabilities: protectedProcedure
    .input(z.object({
      profile: z.enum(["full", "lightweight", "stealth", "recon_only"]),
    }))
    .query(({ input }) => {
      return getCapabilitiesForProfile(input.profile as AgentProfile);
    }),

  /** Generate an installer script for a specific platform */
  generateInstaller: protectedProcedure
    .input(z.object({
      platform: z.enum(["linux_x64", "linux_arm64", "windows_x64", "macos_x64", "macos_arm64"]),
      profile: z.enum(["full", "lightweight", "stealth", "recon_only"]).default("full"),
      callbackHost: z.string(),
      callbackPort: z.number().min(1).max(65535).default(443),
      beaconProtocol: z.enum(["https", "dns", "websocket"]).default("https"),
      beaconIntervalSec: z.number().min(5).max(86400).default(60),
      jitterPercent: z.number().min(0).max(100).default(10),
      agentName: z.string().optional(),
      group: z.string().optional(),
      encrypted: z.boolean().default(true),
      obfuscated: z.boolean().default(false),
      killDate: z.string().optional(),
      maxRetries: z.number().min(0).max(100).default(10),
    }))
    .mutation(({ input }) => {
      return generateInstaller({
        platform: input.platform as AgentPlatform,
        profile: input.profile as AgentProfile,
        callbackHost: input.callbackHost,
        callbackPort: input.callbackPort,
        beaconProtocol: input.beaconProtocol as BeaconProtocol,
        beaconIntervalSec: input.beaconIntervalSec,
        jitterPercent: input.jitterPercent,
        agentName: input.agentName,
        group: input.group,
        encrypted: input.encrypted,
        obfuscated: input.obfuscated,
        killDate: input.killDate,
        maxRetries: input.maxRetries,
      });
    }),
});
